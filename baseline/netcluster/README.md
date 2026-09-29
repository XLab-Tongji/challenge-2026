# NetCluster 当前流水线

NetCluster 由四类异常检测模块、双态故障推理、事后根因排序和提交文件写入组成。所有模块以 UTC 分钟和统一异常事件契约连接。

| 阶段 | 实现 | 入口 |
| --- | --- | --- |
| 指标异常 | `anomaly_detector/metric/` | `python -m baseline.netcluster.cli.run_metric_anomaly_detection` |
| 指标调参结果拼接 | `cli/build_optimized_metric_results.py` | `python -m baseline.netcluster.cli.build_optimized_metric_results` |
| 日志异常 | `anomaly_detector/log/` | `python -m baseline.netcluster.cli.run_log_anomaly_detection` |
| Traffic Flow 异常 | `anomaly_detector/network_flow/traffic_flow_v3.py` | `python -m baseline.netcluster.cli.run_traffic_flow_anomaly_detection` |
| NetFlow 五元组异常 | `anomaly_detector/network_flow/five_tuple.py` | `python -m baseline.netcluster.cli.run_netflow_5tuple_detection` |
| 故障检测与根因推理 | `fault_detection/evidence_cluster_machine/` | `python -m baseline.netcluster.cli.run_evidence_cluster_state_machine` |
| 故障长度裁剪 | `fault_detection/postprocess.py` | `python -m baseline.netcluster.cli.run_fault_postprocessing` |

四个检测器分别生成 `evidence_events.jsonl` 和 `observation_coverage.jsonl`。指标调参结果由 `build_optimized_metric_results.py` 与未修改指标的原结果拼接。推理入口默认读取优化后的指标结果及其他三类异常结果，按分钟运行 `NORMAL/FAULT` 状态机，对故障区间进行根因排序，最后生成符合官方格式的 `predictions.jsonl`。输入路径、先验配置、运行参数和输出目录均可通过命令行覆盖；使用 `--help` 查看参数。

已有状态机结果可运行 `python -m baseline.netcluster.cli.run_fault_postprocessing`。默认读取 `outputs/submission/raw/`，生成 `outputs/submission/result/predictions.jsonl`；可用 `--source` 和 `--output` 指定其他目录。该步骤只把超过 30 分钟的故障按证据裁剪，保留原有故障数量、类型和根因，不处理故障之间的时间间隔，也不修改输入结果。

完整处理逻辑见 [故障检测与根因推理技术报告](../../docs/fault_detection_and_rca_technical_report.md)。四类检测器见 [异常检测技术报告](../../docs/anomaly_detection_technical_report.md)。
