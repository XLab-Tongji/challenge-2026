# 系统架构

整个实验环境共由八个区域组成，其中包括三个核心区域：北大，武汉，上海；五个边缘接入区域：沈阳，西安，南京、成都、广州。区域之间按照非全互联方式连接，每个区域作为一个相对独立的网络单元，区域内负责本地业务承载，区域间负责跨区域通信，形成一个具有多跳传播、路径绕行和跨区域访问特征的骨干网拓扑，为链路故障、路由故障、防火墙故障等多类异常提供真实场景。



每个区域内部拓扑采用分层结构设计，共分为五层，单区域共包含4台路由器，4台交换机，1台防火墙以及6台业务虚拟机。区域内部部署traffic-vm、多个service-vm及monitor-vm，分别承担流量生成，业务服务和监控采集任务等。其中，traffic-vm 产生主动流量，其运行状态及访问结果形成 Flow 指标；路由器通过 NetFlow 导出组件输出实际转发的流量记录，并由监控端完成采集、聚合和入库。业务流量依次经过接入交换机、防火墙、核心路由器和边界路由器，实现对链路、路由、服务的全栈观测。



故障类型覆盖链路级、防火墙级、路由级、资源级和服务级故障。其中，链路级故障用于模拟网络传输过程中的异常状态，影响网络通信质量；防火墙级故障用于模拟网络安全设备运行异常，影响流量转发过程；路由级故障用于模拟网络路径选择异常，影响数据转发行为；资源级故障用于模拟设备资源不足导致的性能下降；服务级故障用于模拟业务服务异常，影响应用访问能力。

# 观测数据

## 数据组织与适用网元

以下以 `data/updated/first_stage/` 为准。数据按 `<region>/<entity>/<category>/` 存放；区域代码为 `beida`、`shenyang`、`xian`、`chengdu`、`wuhan`、`shanghai`、`nanjing`、`guangzhou`。网元包括每区域的边界路由器 `br-1/2`、核心路由器 `cr-1/2`、防火墙 `fw`、业务虚拟机 `service-vm-1/2/3` 和流量虚拟机 `traffic-vm`。表中的“可空”表示 CSV 中可能出现 `NULL` 或空值；时间字段除特别说明外为 UTC，格式为 `YYYY-MM-DD HH:MM:SS`。

| 网元 | 日志 `log` | 指标 `metric` | `netflow_5tuple` | `traffic_flow` |
| --- | --- | --- | --- | --- |
| `br-1/2` 边界路由器 | `frr_syslog_events.csv` | `node_metrics.csv`、`interface_metrics.csv`、`routing_metrics.csv`、`scrape_health.csv` | `netflow_5tuple.csv` | — |
| `cr-1/2` 核心路由器 | `frr_syslog_events.csv` | 同上；BGP 指标列可为空 | `netflow_5tuple.csv` | — |
| `fw` 防火墙 | — | `node_metrics.csv`、`interface_metrics.csv`、`scrape_health.csv` | — | — |
| `service-vm-1/2/3` 业务虚拟机 | — | `node_metrics.csv`、`interface_metrics.csv`、`scrape_health.csv` | — | — |
| `traffic-vm` 流量虚拟机 | — | `node_metrics.csv`、`interface_metrics.csv`、`scrape_health.csv` | — | `series_index.csv` 及按序列拆分的 CSV |

指标 CSV 是宽表，每行对应一个 `timestamp`。接口列以 `ensN_` 为前缀；路由列以 `__label_urlencoded_` 后缀区分标签组合；采集健康列以 exporter 和目标地址组成前缀。下表使用 `<接口>_`、`<指标>__label_urlencoded_<标签>` 和 `<exporter>__target_urlencoded_<目标>__` 表示实际列名模式；标签为 URL 编码的 `key="value"` 组合。列存在不代表该时刻有值。

## 日志：路由器 FRR 事件

`br-1/2`、`cr-1/2` 的 `log/frr_syslog_events.csv` 使用相同字段，逐行记录事件，而非固定周期采样。

| 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- |
| `entity` | 产生事件的路由器名，如 `br-1` | 字符串 |
| `id` | 事件记录编号 | 整数 |
| `received_at` | 日志接收时间，秒精度 | UTC 时间字符串 |
| `event_time` | 设备事件时间，秒精度 | UTC 时间字符串 |
| `received_at_raw` | 原始接收时间，含微秒与 `+00:00` | ISO 8601 时间字符串 |
| `event_time_raw` | 原始事件时间，含微秒与 `+00:00` | ISO 8601 时间字符串 |
| `source_ip` | 发送日志的路由器 IP | IP 地址字符串 |
| `hostname` | 设备主机名 | 字符串 |
| `region` | 区域名称，如 `ccf-aiops-广州` | 字符串 |
| `facility` | syslog facility，如 `local5` | 字符串 |
| `severity` | 日志级别，如 `info`、`warning` | 字符串 |
| `severity_code` | syslog 级别数字代码，如 info 为 6 | 整数 |
| `program` | FRR 守护进程，如 `bgpd`、`ospf6d` | 字符串 |
| `pid` | 进程 ID | 整数，可空 |
| `message` | 事件正文 | 字符串 |
| `inserted_at` | 事件入库时间，含小数秒 | UTC 时间字符串 |

## 指标：各网元资源、接口、路由与采集状态

`metric/node_metrics.csv` 适用于路由器、防火墙、业务虚拟机和流量虚拟机。

| 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- |
| `timestamp` | 指标采样时间 | UTC 时间字符串 |
| `cpu_usage` | CPU 使用量；数据中可大于 1，不应直接当作 0～1 比例 | 浮点数 |
| `load1` | 过去 1 分钟平均系统负载 | 浮点数 |
| `load5` | 过去 5 分钟平均系统负载 | 浮点数 |
| `memory_available_ratio` | 可用内存占总内存比例 | 浮点数 |
| `swap_used_ratio` | 已用交换空间占比 | 浮点数 |
| `disk_read_rate` | 磁盘读取速率，字节/秒 | 浮点数 |
| `disk_write_rate` | 磁盘写入速率，字节/秒 | 浮点数 |
| `disk_io_util` | 磁盘 I/O 利用量；数据中可大于 1 | 浮点数 |
| `filesystem_used_ratio` | 文件系统已使用比例 | 浮点数 |
| `inode_used_ratio` | inode 已使用比例 | 浮点数 |
| `open_fd_ratio` | 打开文件描述符占比 | 浮点数 |
| `process_count` | 进程数量 | 整数或浮点数 |

`metric/interface_metrics.csv` 也适用于上述全部网元。每个实际列名由接口名与下列字段拼接，如 `ens4_rx_bytes_rate`。路由器列覆盖 `ens3`～`ens12`，其他网元覆盖 `ens3`～`ens6`；列存在时接口也可能没有业务流量。

| 字段名称（`<接口>_` 后缀） | 物理含义 | 值类型 |
| --- | --- | --- |
| `timestamp` | 指标采样时间；不带接口前缀 | UTC 时间字符串 |
| `if_role` | 接口角色，如 `backbone`、`business`、`service`；未标注时为 `NULL` | 字符串，可空 |
| `rx_bytes_rate` | 接收字节速率，字节/秒 | 浮点数 |
| `tx_bytes_rate` | 发送字节速率，字节/秒 | 浮点数 |
| `rx_packets_rate` | 接收报文速率，包/秒 | 浮点数 |
| `tx_packets_rate` | 发送报文速率，包/秒 | 浮点数 |
| `rx_drop_rate` | 接收方向丢包速率，包/秒 | 浮点数 |
| `tx_drop_rate` | 发送方向丢包速率，包/秒 | 浮点数 |
| `rx_error_rate` | 接收方向错误报文速率，包/秒 | 浮点数 |
| `tx_error_rate` | 发送方向错误报文速率，包/秒 | 浮点数 |
| `carrier_changes` | 接口载波状态变化累计次数 | 数值 |

`metric/routing_metrics.csv` 仅适用于 `br-1/2` 和 `cr-1/2`。同一指标可按 `peer`、`remote_as`、`state`、`prefix`、`protocol`、`interface`、`neighbor_id`、`next_hop`、`dev`、`metric`、`route_index`、`nh_index` 等标签生成多列。核心路由器没有 BGP 会话，因此相应列可为空。

| 字段名称（标签前的指标名） | 物理含义 | 值类型 |
| --- | --- | --- |
| `timestamp` | 指标采样时间 | UTC 时间字符串 |
| `bgp_command_success` | BGP 状态采集命令是否成功 | 0/1 数值，可空 |
| `bgp_peer_count` | BGP 邻居数量 | 数值，可空 |
| `bgp_peer_prefix_received` | 从指定 BGP 邻居收到的路由前缀数量 | 数值，可空 |
| `bgp_peer_prefix_sent` | 向指定 BGP 邻居发送的路由前缀数量 | 数值，可空 |
| `bgp_peer_up` | 指定 BGP 邻居会话是否建立 | 0/1 数值，可空 |
| `bgp_peer_uptime_seconds` | 指定 BGP 邻居会话已持续时间，秒 | 数值，可空 |
| `ipv6_default_route_changed_total` | 默认 IPv6 路由变化累计次数 | 数值 |
| `ipv6_default_route_info` | 标签所描述的默认路由条目是否存在；下一跳等属性位于列名标签 | 0/1 数值，可空 |
| `ipv6_route_change_total` | 指定 IPv6 前缀的路由变化累计次数 | 数值，可空 |
| `ipv6_route_count` | 按路由协议统计的 IPv6 路由数量 | 数值，可空 |
| `ipv6_route_exists` | 指定 IPv6 前缀是否在路由表中 | 0/1 数值，可空 |
| `ipv6_route_nexthop_info` | 标签所描述的 IPv6 路由下一跳条目是否存在；前缀、下一跳、接口等属性位于列名标签 | 0/1 数值，可空 |
| `ospf6_interface_cost` | 指定 OSPFv3 接口开销 | 数值，可空 |
| `ospf6_interface_enabled` | 指定 OSPFv3 接口是否启用 | 0/1 数值，可空 |
| `ospf6_neighbor_state_code` | OSPFv3 邻居状态编码；状态名称位于列名标签，如 `Full` | 数值，可空 |

`metric/scrape_health.csv` 适用于全部有指标的网元。路由器通常包含 `node_exporter` 与 `routing_exporter` 两组目标，其余网元包含 `node_exporter`。如 `node_exporter__target_urlencoded_%5B...%5D%3A9100__scrape_up`。

| 字段名称（目标前缀后的后缀） | 物理含义 | 值类型 |
| --- | --- | --- |
| `timestamp` | 采集时间 | UTC 时间字符串 |
| `scrape_up` | 本次抓取是否成功 | 0/1 数值 |
| `scrape_duration_seconds` | 本次抓取耗时，秒 | 浮点数 |
| `scrape_samples` | 本次抓取返回的样本数 | 整数或浮点数 |
| `scrape_error` | 抓取错误信息；正常时通常为 `NULL` | 字符串，可空 |

## NetFlow 五元组：边界与核心路由器

`br-1/2`、`cr-1/2` 的 `netflow/netflow_5tuple.csv` 均按路由器与接口记录分钟级聚合的流。以下字段以广州 `br-1` 的文件结构为例；`protocol` 是 IP 协议号，端口在无端口协议中可为 0，`if_role` 与区域推断结果可为空。

| 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- |
| `entity` | 导出流记录的路由器名 | 字符串 |
| `minute_utc` | 流量归属的 UTC 分钟 | UTC 时间字符串 |
| `region_code` | 区域英文代码 | 字符串 |
| `region` | 区域名称 | 字符串 |
| `interface_id` | 路由器导出接口，如 `ens4` | 字符串 |
| `if_role` | 导出接口角色 | 字符串，可空 |
| `collector_port` | 该接口对应的 NetFlow 采集端口 | 整数 |
| `protocol` | IP 协议号，如 TCP=6、UDP=17、ICMPv6=58、OSPF=89 | 整数 |
| `protocol_name` | IP 协议名称 | 字符串 |
| `src_addr` | 源 IP 地址 | IP 地址字符串 |
| `src_port` | 源端口号 | 整数 |
| `src_region_inferred` | 根据源地址推断的区域 | 字符串，可空 |
| `dst_addr` | 目的 IP 地址 | IP 地址字符串 |
| `dst_port` | 目的端口号 | 整数 |
| `dst_region_inferred` | 根据目的地址推断的区域 | 字符串，可空 |
| `packets` | 此分钟、接口及五元组内的报文数 | 整数 |
| `bytes` | 此分钟、接口及五元组内的字节数 | 整数 |
| `flow_record_count` | 汇总前的原始流记录条数 | 整数 |
| `first_seen` | 汇总流中最早观测时间 | UTC 时间字符串 |
| `last_seen` | 汇总流中最晚观测时间 | UTC 时间字符串 |

## Traffic Flow：流量虚拟机主动探测

每个区域 `traffic-vm/traffic_flow/series_index.csv` 给出 `dns`、`web`、`auth`、`elephant` 等流序列的索引；每条序列由 `file_path` 指向同目录下的 CSV。索引字段如下，序列文件中同名字段含义与类型一致。

| 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- |
| `series_key` | 流序列的稳定哈希标识 | 字符串 |
| `flow_type` | 流类型：`dns`、`web`、`auth`、`elephant` | 枚举字符串 |
| `source_region` | 发起探测的区域代码 | 字符串 |
| `source_ip` | 探测源 IP | IP 地址字符串 |
| `target_region` | 探测目标区域代码 | 字符串 |
| `target_domain` | 目标域名 | 字符串 |
| `protocol` | 应用探测协议，如 `udp`、`http` | 字符串 |
| `file_path` | 该序列 CSV 的相对文件名，仅索引表有 | 字符串 |

序列 CSV 的公共字段如下；`id`、时间与统计值均属于该条流序列，累计量不是单分钟增量。观测时刻与 Prometheus 原始采样时刻分别保留。

| 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- |
| `timestamp_utc` | 对齐后的观测分钟 | UTC 时间字符串 |
| `prometheus_sample_time_utc` | Prometheus 样本原始时间 | UTC 时间字符串 |
| `id` | 样本记录编号 | 整数 |
| `series_key`、`flow_type`、`source_region`、`source_ip`、`target_region`、`target_domain`、`protocol` | 流序列身份与探测两端；含义同索引表 | 字符串 |
| `active` | 采样时流是否活跃 | 0/1 数值 |
| `batch_concurrency` | 探测批次的并发量 | 数值 |
| `batches_started_total` | 已启动批次累计数 | 数值 |
| `batches_completed_total` | 已完成批次累计数 | 数值 |
| `batches_failed_total` | 已失败批次累计数 | 数值 |
| `batches_timeout_total` | 已超时批次累计数 | 数值 |
| `requests_total` | 已发起请求累计数 | 数值 |
| `success_total` | 成功请求累计数 | 数值 |
| `error_total` | 错误请求累计数 | 数值 |
| `bytes_sent_total` | 已发送字节累计数 | 数值 |
| `bytes_received_total` | 已接收字节累计数 | 数值 |
| `duration_seconds_sum` | 批次或请求持续时长累计和，秒 | 浮点数 |
| `active_seconds_total` | 活跃持续时长累计和，秒 | 浮点数 |
| `duration_seconds_count` | 时长观测累计次数 | 数值 |
| `batch_duration_seconds` | 最近批次耗时，秒 | 浮点数 |
| `last_batch_timestamp_seconds` | 最近批次的 Unix 时间戳，秒 | 浮点数 |
| `observed_qps` | 观测请求速率，次/秒 | 浮点数，可空 |
| `latency_mean_seconds` | 平均请求时延，秒 | 浮点数，可空 |
| `latency_p95_seconds` | 请求时延 P95，秒 | 浮点数，可空 |

`dns`、`web`、`auth` 序列还包含延迟直方图字段；`elephant` 序列则包含传输质量字段。某些质量指标在样本中可为 `NULL`。

| 适用流类型 | 字段名称 | 物理含义 | 值类型 |
| --- | --- | --- | --- |
| `dns`、`web`、`auth` | `request_latency_seconds_bucket_le_{0_01,0_025,0_05,0_1,0_25,0_5,1,2_5,5,plus_inf}` | 延迟不超过相应秒阈值的累计请求数；花括号内每项分别替换为实际列名后缀 | 数值 |
| `dns`、`web`、`auth` | `request_latency_seconds_sum` | 直方图观测的请求延迟累计和，秒 | 浮点数 |
| `dns`、`web`、`auth` | `request_latency_seconds_count` | 直方图观测的请求累计数 | 数值 |
| `elephant` | `throughput_bps` | 传输吞吐量，bit/s | 浮点数，可空 |
| `elephant` | `retransmits_total` | 重传累计次数 | 数值，可空 |
| `elephant` | `loss_rate` | 丢包率 | 浮点数，可空 |
| `elephant` | `jitter_seconds` | 时延抖动，秒 | 浮点数，可空 |
