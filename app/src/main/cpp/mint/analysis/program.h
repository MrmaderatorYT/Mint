#pragma once

#include <map>
#include "mint/db/database.h"
#include "mint/types/data_type_manager.h"
#include "mint/loader/memory_map.h"
#include "mint/analysis/local_variables.h"

namespace mint {

// Central user decisions, type library, memory blocks and reference index.
// Durable user state is an overlay over immutable input. Session stores derived
// code/references separately with a source/model/version dependency key. A failed
// user transaction never changes the live model.
class Program {
public:
    explicit Program(u8 pointerSize = 8) : types_(pointerSize), importedTypes_(pointerSize) {}
    // Loader/debug types are reproducible derived evidence. User library entries
    // override them, while unsupported layouts are never manufactured.
    Status setImportedTypes(const DataTypeManager& types);
    Status open(const std::string& path, const std::string& source = {});
    Status edit(Address address, const std::string& kind, const std::string& value);
    Status editLocal(Address functionEntry, const std::string& identity,
                     const std::string& name, const std::string& type);
    std::vector<LocalVariableEdit> locals(Address functionEntry) const;
    Status undo();
    Status redo();
    std::string get(Address address, const std::string& kind) const;
    std::vector<ProgramAnnotation> annotations() const;
    const DataTypeManager& types() const { return types_; }
    u64 revision() const { return revision_; }
    const std::string& path() const { return path_; }
    void bindMemory(const MemoryMap& memory) { memory_ = memory; }
    const MemoryMap& memory() const { return memory_; }
    struct Reference { Address from, to; std::string kind; };
    struct DependencyRange { Address start, end; };
    // One independently recomputable reference result. Dependencies include the
    // instructions and immutable memory consulted while resolving SSA values.
    // kNoAddress owns relocation and explicitly typed-data references.
    struct ReferenceGroup {
        Address owner = kNoAddress;
        std::vector<Reference> references;
        std::vector<DependencyRange> dependencies;
        bool conservative = false;
    };
    void setReferences(std::vector<Reference> references);
    void setReferenceGroups(std::vector<ReferenceGroup> groups);
    const std::vector<ReferenceGroup>& referenceGroups() const { return referenceGroups_; }
    std::vector<Reference> referencesAt(Address address) const;
    void invalidateReferences(bool retainGroups = false);
    bool referencesReady() const { return referencesReady_; }
    const std::vector<Reference>& references() const { return references_; }
private:
    using Key = std::pair<Address, std::string>;
    using State = std::map<Key, std::string>;
    Status save(const State& state);
    Status validate(const State& state, DataTypeManager* types) const;
    struct Change { Key key; std::string before, after; bool hadBefore, hasAfter; };
    Status replay(const Change& change, bool forward);
    std::string path_;
    State state_;
    std::vector<Change> undo_, redo_;
    DataTypeManager types_;
    DataTypeManager importedTypes_;
    MemoryMap memory_;
    u64 revision_ = 0;
    std::vector<Reference> references_;
    std::vector<ReferenceGroup> referenceGroups_;
    std::map<Address, std::vector<size_t>> incoming_, outgoing_;
    bool referencesReady_ = false;
};
} // namespace mint
