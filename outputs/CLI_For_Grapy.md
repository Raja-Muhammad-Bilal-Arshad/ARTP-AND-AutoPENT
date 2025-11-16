Firstly you Should be in the ROOT FOLDER


RUN THE FOLLOWING FOR THE HEATMAP

python3 tools/analyze_ad_users_vuln_weighted_heatmap.py \
  --reports-dir reports \
  --out outputs/ad_user_heatmap_graph.png \
  --summary outputs/ad_user_heatmap_summary.csv


RUN THE FOLLOWING FOR THE visual map of risk & privilege(Graph) AND per-user risk score and privileged flag(csv)




python3 tools/analyze_ad_users_vuln_weighted.py \
  --reports-dir reports \
  --out outputs/ad_user_weighted_risk_graph.png \
  --summary outputs/ad_user_weighted_risk_summary.csv
