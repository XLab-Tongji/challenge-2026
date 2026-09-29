# AIOps Challenge 2026

本仓库保留赛事 SDK 与评测器、BiAn 和 NetCluster 两套 Baseline，以及最新一轮的异常检测和提交结果。

## 目录

| 路径 | 内容 |
| --- | --- |
| `aiops_challenge_2026/` | 数据接口、公开配置和本地评测器 |
| `baseline/bian/` | BiAn 参考 Baseline 和样例运行入口 |
| `baseline/netcluster/` | 四类异常检测、双态故障检测与根因推理、30 分钟长度裁剪 |
| `data/processed/`、`data/updated/` | 处理后数据和更新数据 |
| `outputs/metric_anomalies/`、`outputs/log_anomalies/` | 最新指标、日志异常结果 |
| `outputs/traffic_flow_anomalies/`、`outputs/netflow_anomalies/` | 最新 Traffic Flow、NetFlow 异常结果 |
| `outputs/submission/raw/`、`outputs/submission/result/` | 最新故障推理中间结果和裁剪结果 |
| `submission/predictions.jsonl` | 当前可提交文件；同目录提供提交和查分脚本 |
| `scripts/` | 原始数据预处理脚本 |
| `docs/` | 元数据、异常检测、故障检测与根因推理技术报告 |
| `examples/`、`sample/` | 官方示例与样例数据，内容保持不变 |

## 安装

```bash
python -m pip install -e .
python -m pip install -e ".[log]"  # 运行日志检测时需要 Drain3
python -m pip install -e ".[llm]"  # 运行 BiAn 的 LLM 路径时需要
```

## 复现 NetCluster 结果

以下命令在仓库根目录运行。现有四类最新异常结果已经位于 `outputs/`，可以直接从故障推理步骤开始。

```bash
python -m baseline.netcluster.cli.run_evidence_cluster_state_machine
python -m baseline.netcluster.cli.run_fault_postprocessing
```

故障推理读取四类 `evidence_events.jsonl` 和 `observation_coverage.jsonl`。后处理只对超过 30 分钟的故障按证据裁剪，不合并、补报或按故障间隔筛选。将 `outputs/submission/result/predictions.jsonl` 复制为 `submission/predictions.jsonl` 即得到当前提交文件。

如需重新检测异常，运行各模块入口：

```bash
python -m baseline.netcluster.cli.run_metric_anomaly_detection
python -m baseline.netcluster.cli.build_optimized_metric_results
python -m baseline.netcluster.cli.run_log_anomaly_detection
python -m baseline.netcluster.cli.run_traffic_flow_anomaly_detection
python -m baseline.netcluster.cli.run_netflow_5tuple_detection --data-root data/updated/first_stage --output-dir outputs/netflow_anomalies
```

指标检测先生成完整基础结果，再把调参的指标与未改动指标拼接；日志检测需要 `.[log]`。各入口可用 `--help` 查看参数。

## 验证与提交

```bash
python -m pytest tests
python -m aiops_challenge_2026.evaluator --ground-truth sample/ground_truth.jsonl --predictions examples/predictions.jsonl
python submission/submit.py submission/predictions.jsonl
```

样例真值仅适用于 `sample/` 的示例预测，不能用于评估完整测试集的得分。实际提交会访问评测服务器；查看提交状态使用 `python submission/check_score.py <SUBMISSION_ID>`。

技术细节见 [异常检测技术报告](docs/anomaly_detection_technical_report.md) 和[故障检测与根因推理技术报告](docs/fault_detection_and_rca_technical_report.md)。BiAn 参考方法见 [Towards LLM-Based Failure Localization in Production-Scale Networks](https://doi.org/10.1145/3718958.3750505)。
