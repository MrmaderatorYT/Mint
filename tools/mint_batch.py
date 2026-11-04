#!/usr/bin/env python3
"""Run independent, read-only Mint analyses with bounded concurrency."""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
from pathlib import Path
import signal
import subprocess
import sqlite3
import sys
import threading
import time
import fcntl
from mint_batch_checkpoint import Checkpoint, digest, attempt_id

READ_COMMANDS = ("json", "summary", "functions", "types", "types-c", "prototypes", "signatures", "cxx", "dwarf")
ADDRESS_COMMANDS = ("listing", "decompile", "ir", "cfg", "refs", "provenance", "abi", "locals", "source")


def address(value):
    if len(value) > 128 or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise argparse.ArgumentTypeError("address must be unsigned decimal or 0x-prefixed hexadecimal")
    number = int(value, 16 if value.lower().startswith("0x") else 10)
    if number > 0xffffffffffffffff:
        raise argparse.ArgumentTypeError("address exceeds 64 bits")
    return f"0x{number:x}"


def positive_int(value):
    number = int(value)
    if not 1 <= number <= 64:
        raise argparse.ArgumentTypeError("must be between 1 and 64")
    return number


def timeout_seconds(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return number


def stop_process(process):
    # Also stop descendants (for example a tool launched through a wrapper).
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--input-list", type=Path, help="UTF-8 file: one input path per line, relative to the list")
    parser.add_argument("--tool", required=True, type=Path, help="mint_headless executable")
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    parser.add_argument("--resume", action="store_true", help="resume an existing checkpoint and retry incomplete jobs")
    parser.add_argument("--jobs", type=positive_int, default=1)
    parser.add_argument("--timeout", type=timeout_seconds, default=300.0)
    parser.add_argument("--max-output-bytes", type=int, default=64 * 1024 * 1024, help="maximum bytes per output stream")
    parser.add_argument("--command", choices=READ_COMMANDS + ADDRESS_COMMANDS, default="json")
    parser.add_argument("--address", type=address, help="address for address-based commands (same for every input)")
    mapping = parser.add_mutually_exclusive_group()
    mapping.add_argument("--raw", nargs=3, metavar=("ARCH", "BASE", "ENTRY"))
    mapping.add_argument("--macho", metavar="ARCH")
    parser.add_argument("--raw-endian", choices=("little", "big"))
    args = parser.parse_args(argv)
    if (args.command in ADDRESS_COMMANDS) != (args.address is not None):
        parser.error("--address is required for address-based commands and invalid for other commands")
    if args.raw_endian and not args.raw:
        parser.error("--raw-endian requires --raw")
    if args.max_output_bytes < 1:
        parser.error("--max-output-bytes must be positive")
    if args.input_list:
        try:
            with args.input_list.open("rb") as stream:
                contents = stream.read(32 * 1024 * 1024 + 1)
            if len(contents) > 32 * 1024 * 1024:
                parser.error("input list exceeds 32 MiB")
            parent = args.input_list.resolve().parent
            args.inputs.extend(parent / line for line in contents.decode("utf-8").splitlines() if line)
        except (OSError, UnicodeError) as error:
            parser.error(f"cannot read input list: {error}")
    if not args.inputs:
        parser.error("at least one input or --input-list is required")
    tool = args.tool.resolve()
    if not tool.is_file() or not os.access(tool, os.X_OK):
        parser.error("--tool must be an executable file")
    if len(args.inputs) > 100000:
        parser.error("at most 100000 inputs are supported")
    inputs = [str(source.resolve()) for source in args.inputs]
    config = dict(command=args.command, raw=args.raw, macho=args.macho,
                  timeout=args.timeout, max_output_bytes=args.max_output_bytes,
                  tool=str(tool))
    if args.raw_endian:
        config["raw_endian"] = args.raw_endian
    if args.address is not None:
        config["address"] = args.address
    try:
        if args.resume:
            if not args.output.is_dir() or args.output.is_symlink():
                raise ValueError("resume requires an existing output directory")
        else:
            args.output.mkdir(parents=True, exist_ok=False)
        lock_path = args.output / '.batch.lock'
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        lock = os.fdopen(lock_fd, 'r+')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        checkpoint = Checkpoint(args.output, config, inputs, args.resume)
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.error(f"cannot open batch checkpoint: {error}")
    # Bind reuse to the executable, this runner, and the engine shared library
    # in the executable directory when present. A changed engine reruns jobs.
    engine = hashlib.sha256()
    for path in [tool, Path(__file__).resolve(), Path(__file__).with_name('mint_batch_checkpoint.py'),
                 tool.parent / 'libmint_engine.dylib', tool.parent / 'libmint_engine.so']:
        engine.update(os.fsencode(str(path)))
        fingerprint = digest(path)
        if path == tool and fingerprint is None:
            parser.error('cannot hash headless executable')
        engine.update((fingerprint or 'missing').encode())
    engine_hash = engine.hexdigest()

    cancelled = threading.Event()
    previous_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[sig] = signal.signal(sig, lambda *_: cancelled.set())

    def analyze(item):
        index, source = item
        try:
            source = str(source.resolve())
            if "\0" in source:
                raise ValueError("input path contains a NUL byte")
        except (OSError, RuntimeError, ValueError) as error:
            return dict(input=str(source), output=None, stderr=None, status="failed",
                        exit_code=None, elapsed_seconds=0, error=str(error))
        identity = f"{index:06d}-" + hashlib.sha256(os.fsencode(source)).hexdigest()[:16] + "-" + attempt_id()
        output_name = identity + (".json" if args.command == "json" else ".txt")
        error_name = identity + ".stderr.txt"
        result = dict(input=source, output=output_name, stderr=error_name,
                      status="cancelled", exit_code=None)
        if cancelled.is_set():
            result.update(output=None, stderr=None, elapsed_seconds=0)
            return result
        command = [str(tool), source]
        if args.raw:
            command += ["--raw", *args.raw]
        if args.macho:
            command += ["--macho", args.macho]
        if args.raw_endian:
            command += ["--raw-endian", args.raw_endian]
        command.append(args.command)
        if args.address is not None:
            command.append(args.address)
        start = time.monotonic()
        process = None
        temporary = args.output / (output_name + ".partial")
        try:
            # Stream directly to disk; large JSON never accumulates in Python.
            with temporary.open("xb") as stdout, (args.output / error_name).open("xb") as stderr:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=os.name == "posix")
                exceeded = threading.Event()
                stream_errors = []
                def drain(source, destination):
                    remaining = args.max_output_bytes
                    try:
                        while True:
                            data = os.read(source.fileno(), 65536)
                            if not data:
                                break
                            destination.write(data[:remaining])
                            destination.flush()
                            if len(data) > remaining:
                                exceeded.set()
                            remaining = max(0, remaining - len(data))
                    except OSError as error:
                        stream_errors.append(str(error))
                    finally:
                        source.close()
                readers = [threading.Thread(target=drain, args=(source, destination))
                           for source, destination in ((process.stdout, stdout), (process.stderr, stderr))]
                for reader in readers:
                    reader.start()
                while True:
                    if stream_errors or exceeded.is_set() or cancelled.is_set() or time.monotonic() - start >= args.timeout:
                        result["status"] = "failed" if stream_errors else "output_limit" if exceeded.is_set() else "cancelled" if cancelled.is_set() else "timeout"
                        stop_process(process)
                        break
                    try:
                        code = process.wait(timeout=0.1)
                        result["status"] = "ok" if code == 0 else "failed"
                        break
                    except subprocess.TimeoutExpired:
                        pass
                # A descendant retaining an inherited pipe must not hang the runner.
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for reader in readers:
                    reader.join()
                if stream_errors:
                    result.update(status="failed", error=stream_errors[0])
                elif exceeded.is_set():
                    result["status"] = "output_limit"
                result["exit_code"] = process.returncode
            if result["status"] == "ok":
                temporary.replace(args.output / output_name)
            else:
                # Failed/truncated output must never look like a complete JSON.
                result["output"] = temporary.name
        except OSError as error:
            if process is not None:
                stop_process(process)
            result.update(status="failed", error=str(error), output=temporary.name)
        result["elapsed_seconds"] = round(time.monotonic() - start, 6)
        return result

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            # Keep only jobs futures live even for a very large input list.
            results = [None] * len(args.inputs)
            input_hashes = [None] * len(inputs)
            todo = []
            for index, source in enumerate(inputs):
                old = checkpoint.reusable(index, source, engine_hash) if args.resume else None
                if old is not None:
                    results[index] = old
                else:
                    input_hashes[index] = digest(source)
                    todo.append((index, Path(source)))
            remaining = iter(todo)
            pending = {}
            for item in remaining:
                pending[executor.submit(analyze, item)] = item[0]
                if len(pending) == args.jobs:
                    break
            while pending:
                done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    index = pending.pop(future)
                    result = future.result()
                    if result['status'] == 'ok' and input_hashes[index] != digest(inputs[index]):
                        result['status'] = 'failed'
                        result['error'] = 'input changed during analysis'
                        if result.get('output'):
                            final_path = args.output / result['output']
                            partial = final_path.with_name(final_path.name + '.partial')
                            final_path.replace(partial)
                            result['output'] = partial.name
                    results[index] = result
                    checkpoint.save(index, input_hashes[index], engine_hash, result)
                    item = next(remaining, None)
                    if item is not None:
                        pending[executor.submit(analyze, item)] = item[0]
        report = dict(schema_version=1, command=args.command, jobs=args.jobs,
                      timeout_seconds=args.timeout, results=results)
        if args.address is not None:
            report["address"] = args.address
        temporary_report = args.output / "report.json.partial"
        temporary_report.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        temporary_report.replace(args.output / "report.json")
    finally:
        checkpoint.close()
        lock.close()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    print(str(args.output / "report.json"))
    return 130 if cancelled.is_set() else int(any(item["status"] != "ok" for item in results))


if __name__ == "__main__":
    sys.exit(main())
