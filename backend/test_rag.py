from rag.rag_retriever import retrieve
results = retrieve('ip malicious detection block investigation vt_malicious=15 abuseipdb_score=100 otx_pulses=50 verdict=malicious threat confirmed abuse botnet c2', k=5, min_score=0.35, ioc_type='ip')
print(f'Resultats : {len(results)}')
for r in results:
    print(f"  score={r['score']} — {r['text'][:70]}")
