# 提交文件

`predictions.jsonl` 是当前由 NetCluster 四类异常结果、故障推理和 30 分钟长度裁剪生成的提交文件，共 418 条预测。其内容与 `../outputs/submission/result/predictions.jsonl` 相同。

在仓库根目录提交：

```bash
python submission/submit.py submission/predictions.jsonl
```

查询提交状态：

```bash
python submission/check_score.py <SUBMISSION_ID>
```

`submit.py` 和 `check_score.py` 只使用 Python 标准库。实际提交会访问评测服务器；本地验证可运行 `python -m aiops_challenge_2026.evaluator --ground-truth sample/ground_truth.jsonl --predictions examples/predictions.jsonl`。样例真值不能评估此完整测试集提交文件的得分。
