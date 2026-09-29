# 异常检测方案技术报告

四类异常检测模块均输出标准证据事件和观测覆盖记录，供故障检测与根因推理使用。

## 指标异常检测技术设计

### 模块职责

从设备和服务指标中识别状态异常、数值偏离及预期观测值缺失，生成按 UTC 分钟定位的异常证据。

### 处理流程

1. 发现并读取指标序列，规范时间、实体、指标标识和原始值；保留有效观测与采集覆盖信息。
2. 按 `metric_detection_rules.json` 将序列路由到状态规则、稀有状态或数值检测。数值路径按配置使用全局 ECOD、局部 MAD 或其组合，并对需要的序列提取残差与趋势变化。
3. 结合历史采样规律检测本应有值却缺失的分钟；缺采事件与一般覆盖未知区分，并保留采集源及预期依据。
4. 将异常点写为标准证据事件，记录观测值、基线、异常方向和原始分数。连续指标点仍按当前实现输出为独立分钟事件，下游按来源关系控制重复贡献。

实现位于 `anomaly_detector/metric/`，入口为 `baseline/netcluster/cli/run_metric_anomaly_detection.py`。检测规则与缺失判定均由配置提供。

### 输出契约

`evidence_events.jsonl` 包含数值、状态及预期缺失事件；`observation_coverage.jsonl` 记录观测状态。事件中的 `start_minute`、`last_seen_minute` 为含端点的实际观测分钟，缺失事件可以参与故障启动、关联与强度计算。最终提交格式见[故障检测与根因推理技术设计](fault_detection_and_rca_technical_report.md)。

## 日志异常检测技术设计

### 模块职责

将路由设备和服务日志转为按分钟对齐的结构化异常事件，为故障状态机提供控制面变化与异常消息证据。

### 处理流程

1. 发现日志文件，解析时间、实体和消息，统一到 UTC 分钟。
2. 使用 Drain 模板归并可变字段；根据显式模板规则、严重级别和关键词筛选异常。
3. 按实体、模板、规则和分钟聚合消息；仅对相邻且同源的异常分钟合并 episode，保留次数、严重级别和来源。
4. 写入标准事件及观测覆盖信息。没有日志不能自动解释为系统正常。

实现位于 `anomaly_detector/log/`，模板和分类规则分别使用 `drain3.ini`、`log_anomaly_keywords.json`；入口为 `baseline/netcluster/cli/run_log_anomaly_detection.py`。

### 输出契约

`evidence_events.jsonl` 表示异常 episode，`observation_coverage.jsonl` 表示有效观测范围。事件字段和时间语义遵循[故障检测与根因推理技术设计](fault_detection_and_rca_technical_report.md)。

## Traffic Flow 异常检测技术设计

### 模块职责

读取主动探测序列，识别请求错误、批次超时和 P95 时延异常，输出可供故障状态机消费的连续异常事件。探测端是观测位置，不能直接认定为故障根因。

### 处理流程

1. 解析探测时间、服务类型、源和目标地区及累计计数器，按序列构建 UTC 分钟观测。
2. 校验相邻计数器增量、请求量和采样间隔；计数器回退、无效窗口与缺采不补零。记录实际观测与覆盖未知区间。
3. 对错误率和超时率应用有效性及异常阈值；对时延使用同序列、同负载档位的历史基线，并检查尾部样本支持。异常样本暂停更新相应基线。
4. 将相邻且持续满足条件的异常分钟合并为 episode；保留序列标识、观测值、基线、负载档位和依赖来源。

当前实现为 `traffic_flow_v3.py`，配置为 `traffic_flow_detection_v3.json`，入口为 `baseline/netcluster/cli/run_traffic_flow_anomaly_detection.py`。默认结果位于 `outputs/traffic_flow_anomalies/`。

### 输出契约

`evidence_events.jsonl` 为标准异常事件输入，采用 `evidence_id`、`episode_id`、`start_minute`、`last_seen_minute`、`entity_id`、`modality`、`feature`、`anomaly_kind`、`raw_score` 和 `attributes` 等字段；事件首末分钟均包含。`observation_coverage.jsonl` 区分已观测分钟与未知区间。两者均为推理输入。

## NetFlow 五元组异常检测技术设计

### 模块职责

从路由器五元组记录提取接口、协议、端口和地区对的流量变化证据，并标记可观测的双向失衡。观测路由器仅代表采集位置。

### 处理流程

1. 按路由器流式读取原始记录，校验五元组、时间与计数值，对同一分钟的流组聚合。
2. 依据接口、协议、端口及可推断地区对构建序列，维护历史稳健基线，识别流量上升、下降及控制流变化。
3. 仅在相反方向仍有充分流量且满足历史基线条件时，生成对向缺失异常；采集记录不存在本身不等于零流量。
4. 将连续异常分钟合并为 episode，并输出事件和路由器观测覆盖。

实现位于 `anomaly_detector/network_flow/five_tuple.py`，配置为 `netflow_5tuple_detection.json`，入口为 `baseline/netcluster/cli/run_netflow_5tuple_detection.py`。当前全量结果目录为 `outputs/netflow_anomalies/`，包括接口流量、地区端口流量、小 UDP 包、控制流及方向失衡事件。

### 输出契约

`evidence_events.jsonl` 保存异常的首末观测分钟、路由器实体、特征、方向、原始分数及来源属性；`observation_coverage.jsonl` 区分已观测和未知区间。两者为状态机输入，不直接确定故障类型或根因。
