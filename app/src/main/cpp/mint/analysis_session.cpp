#include "mint/session.h"
#include "mint/db/analysis_cache.h"
#include "mint_analysis_engine_id.h"

#include <algorithm>
#include <map>
#include <sstream>
#include <set>
#include <tuple>

namespace mint {
namespace {
bool structuralKind(const std::string& kind) {
    return kind=="patch" || kind=="data" || kind=="function" || kind=="type-library";
}
size_t patchSize(const std::string& text) {
    std::istringstream input(text); std::string token; size_t size=0;
    while(input>>token) ++size;
    return size;
}
}

CodeAnalyzer::Options Session::analysisOptions() {
    CodeAnalyzer::Options options;
    options.cancel=&cancel_;
    options.progress=&progress_;
    for(const auto& function:debugInfo_.functions)
        if(!function.declaration && function.entry!=kNoAddress && image_.memory().isExecutable(function.entry))
            options.debugFunctionEntries.push_back(function.entry);
    for(const auto& entry:program_.annotations()) {
        if(entry.kind=="function" && entry.value=="code") options.userFunctionEntries.push_back(entry.address);
        if(entry.kind=="data") {
            const auto size=dataSize(entry.address,entry.value,program_.types());
            if(size) options.excludedRanges.push_back({entry.address,entry.address+size});
        }
    }
    return options;
}

std::string Session::analysisDependencyKey() const {
    // Version the engine/loader contract independently of the user overlay.
    // These hashes guard accidental staleness; they do not authenticate files.
    u64 model=14695981039346656037ull;
    auto byte=[&](u8 value){model^=value;model*=1099511628211ull;};
    auto number=[&](u64 value){for(unsigned i=0;i<8;++i)byte(static_cast<u8>(value>>(i*8)));};
    auto string=[&](const std::string& value){number(value.size());for(unsigned char c:value)byte(c);};
    string(externalDebugDigest_);
    for(const auto& entry:program_.annotations()) if(structuralKind(entry.kind)) {
        number(entry.address);string(entry.kind);string(entry.value);
    }
    for(const auto& block:image_.memory().segments()) {
        number(block.start);number(block.size);number(block.flags);number(block.data.size());string(block.name);
    }
    const CodeAnalyzer::Options options;
    number(options.followCalls);number(options.linearSweepFallback);
    number(options.maxInstructions);number(options.maxFunctions);
    std::ostringstream key;
    key<<"mint-native-analysis-1|"<<MINT_ANALYSIS_ENGINE_ID<<"|"<<program_.get(0,"source")<<"|"<<std::hex<<model;
    return key.str();
}

bool Session::restoreAnalysisCache(const CodeAnalyzer::Options& options) {
    if(analysisCachePath_.empty() || !allowCacheRestore_) return false;
    if(static_cast<u8>(image_.arch())>=static_cast<u8>(Arch::kPluginFirst))return false;
    CachedAnalysis cached;
    auto status=AnalysisCache::load(analysisCachePath_,analysisDependencyKey(),&cached);
    if(!status.ok()) {analysisCacheDiagnostic_="cache not used: "+status.toString();return false;}
    // References are derived, never authoritative user state. Reject impossible
    // source addresses before adopting any part of a cached snapshot.
    for(const auto& reference:cached.references) {
        if(!image_.memory().isMapped(reference.from) || reference.kind.empty()) {
            analysisCacheDiagnostic_="cache not used: invalid reference source";return false;
        }
    }
    status=analyzer_.restore(image_,options,cached.analysis);
    if(!status.ok()) {analysisCacheDiagnostic_="cache not used: "+status.toString();return false;}
    // A group must belong to this snapshot and every retained dependency must
    // remain mapped. A bad dependency cache is a miss, not trusted user state.
    std::set<Address> owners;std::vector<Program::Reference> flattened;
    for(const auto& group:cached.referenceGroups) {
        if(group.owner!=kNoAddress && !analyzer_.functionAt(group.owner))return false;
        owners.insert(group.owner);
        for(const auto& range:group.dependencies) {
            const auto* segment=image_.memory().segmentAt(range.start);
            if(!segment || range.end>segment->end())return false;
        }
        for(const auto& reference:group.references)if(!image_.memory().isMapped(reference.from))return false;
        flattened.insert(flattened.end(),group.references.begin(),group.references.end());
    }
    if(cached.referencesReady && !cached.referenceGroups.empty()) {
        if(!owners.count(kNoAddress))return false;
        for(const auto& function:analyzer_.functions())if(!owners.count(function.entry))return false;
        auto key=[](const auto& reference){return std::tie(reference.from,reference.to,reference.kind);};
        std::sort(flattened.begin(),flattened.end(),[&](const auto& a,const auto& b){return key(a)<key(b);});
        flattened.erase(std::unique(flattened.begin(),flattened.end(),[&](const auto& a,const auto& b){return key(a)==key(b);}),flattened.end());
        if(flattened.size()!=cached.references.size())return false;
        for(size_t i=0;i<flattened.size();++i)if(key(flattened[i])!=key(cached.references[i]))return false;
    }
    if(cached.referencesReady && !cached.referenceGroups.empty())program_.setReferenceGroups(std::move(cached.referenceGroups));
    else if(cached.referencesReady) program_.setReferences(std::move(cached.references));
    else program_.invalidateReferences();
    analysisMode_="restored";analysisFunctionsUpdated_=0;
    analysisReason_="validated source/model/version snapshot";
    analysisCacheDiagnostic_.clear();
    progress_.store(100,std::memory_order_relaxed);
    return true;
}

void Session::saveAnalysisCache() {
    if(analysisCachePath_.empty() || !analyzed_ || isDexLike() || cancel_.load()) return;
    if(static_cast<u8>(image_.arch())>=static_cast<u8>(Arch::kPluginFirst))return;
    CachedAnalysis cached;
    cached.analysis=analyzer_.snapshot();
    cached.referencesReady=program_.referencesReady();
    if(cached.referencesReady) {cached.references=program_.references();cached.referenceGroups=program_.referenceGroups();}
    const auto status=AnalysisCache::save(analysisCachePath_,analysisDependencyKey(),cached);
    if(!status.ok()) analysisCacheDiagnostic_="derived cache could not be saved: "+status.toString();
}

std::string Session::analysisStatusText() const {
    std::string out="mode="+analysisMode_+" functions="+std::to_string(analysisFunctionsUpdated_)+" reason="+analysisReason_+"\n";
    out+="Derived references: "+std::string(program_.referencesReady()?"ready":"lazy / not built")+"; groups updated="+std::to_string(referenceGroupsUpdated_)+"\n";
    if(!analysisCacheDiagnostic_.empty()) out+=analysisCacheDiagnostic_+"\n";
    return out;
}

Status Session::updateAfterEdit(const std::vector<ProgramAnnotation>& before,ElfImage* prepared) {
    using Key=std::pair<Address,std::string>;
    std::map<Key,std::pair<std::string,std::string>> changes;
    for(const auto& entry:before) changes[{entry.address,entry.kind}].first=entry.value;
    for(const auto& entry:program_.annotations()) changes[{entry.address,entry.kind}].second=entry.value;
    bool structural=false,onlyPatches=true,changed=false;
    std::vector<CodeAnalyzer::AddressRange> dirty;
    for(const auto& change:changes) {
        if(change.second.first==change.second.second) continue;
        changed=true;
        if(!structuralKind(change.first.second)) continue;
        structural=true;
        if(change.first.second!="patch") onlyPatches=false;
        else {
            const auto size=std::max(patchSize(change.second.first),patchSize(change.second.second));
            if(size) dirty.push_back({change.first.first,change.first.first+size});
        }
    }
    if(!changed) return Status::success();
    signatures_=SignatureLibrary{};const auto signatureText=program_.get(0,"signature-library");
    if(!signatureText.empty()){const auto status=signatures_.deserialize(signatureText);if(!status.ok())return status;}
    prototypeEvidence_={};prototypeEvidenceBuilt_=false;
    programReport_={};
    if(!structural) {
        analysisMode_="metadata";analysisFunctionsUpdated_=0;
        analysisReason_="user text/prototype changed; discovery and references preserved";
        return Status::success();
    }
    const bool hadAnalysis=analyzed_;
    ElfImage trial;
    if(!prepared) {
        auto status=prepareUserImage(program_.annotations(),program_.types(),&trial);
        if(!status.ok()) return status;
        prepared=&trial;
    }
    image_=std::move(*prepared);program_.bindMemory(image_.memory());
    program_.invalidateReferences(onlyPatches);analyzed_=false;cancel_.store(false);
    analysisCacheDiagnostic_.clear();
    if(hadAnalysis && onlyPatches && !dirty.empty()) {
        CodeAnalyzer::IncrementalResult result;
        const auto status=analyzer_.reanalyzeChanged(image_,analysisOptions(),dirty,&result);
        if(!status.ok()) return status;
        analyzed_=true;analysisMode_=result.used?"incremental":"full";
        analysisFunctionsUpdated_=result.functionsReanalyzed;analysisReason_=result.reason;
        if(result.used)refreshReferences(dirty);else program_.invalidateReferences();
        detectorFindings_.clear();
        if(image_.format()==ImageFormat::kElf64) detectorFindings_=runDetectors(image_);
        saveAnalysisCache();
        return Status::success();
    }
    const bool previous=allowCacheRestore_;allowCacheRestore_=false;
    auto status=analyze();allowCacheRestore_=previous;
    if(status.ok()) analysisReason_="code/data boundaries or type model changed; full discovery";
    return status;
}
} // namespace mint
