// ============================================================
// RAG / Vector Database Unusual Access
// TacticCategory: Collection
// Source: NetworkConnectIP4
//
// Vector databases store sensitive documents as embeddings and
// are queryable by anyone who can reach the local API port.
//
// Covered vector DB ports:
//   ChromaDB  :8000    Qdrant  :6333/:6334
//   Weaviate  :8080    Milvus  :19530
//   LanceDB   :8181    Marqo   :8882
//
// Two signals:
//   1. Non-AI processes connecting to vector DB ports
//   2. High-volume connections (bulk data harvesting)
// ============================================================

// --- Signal 1 & 2: Connections to local vector DB ports ---
#event_simpleName=NetworkConnectIP4

// Only local connections
| RemoteAddressIP4=/(^127\.|^::1|^0\.0\.0\.0)/

// Vector database ports
| RemotePort in (8000, 6333, 6334, 8080, 19530, 8181, 8882)

| UserName != /\$$/

// Classify by accessor type
| case {
    // Known AI/ML framework processes — lower priority but track volume
    FileName=/(python|node|Claude|Cursor|windsurf|code|ollama)\.exe/i =>
        | AccessType := "AI framework (track volume)" ;

    // Browsers — likely a developer admin UI, low risk
    FileName=/(chrome|msedge|firefox|brave)\.exe/i =>
        | AccessType := "Browser (admin UI)" ;

    // Anything else is suspicious
    * =>
        | AccessType := "Unexpected process" ;
}

// Aggregate to surface volume anomalies
| groupBy(
    [ComputerName, UserName, FileName, RemotePort, AccessType],
    function=count(as=ConnectionCount)
)
| sort(ConnectionCount, order=desc)
