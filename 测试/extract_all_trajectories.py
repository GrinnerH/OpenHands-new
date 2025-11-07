#!/usr/bin/env python3
"""
批量提取 output.jsonl 中所有实例的轨迹

用法: python extract_all_trajectories.py <jsonl_file>
"""

import json
import os
import sys


def extract_all_trajectories(jsonl_file: str):
    """提取所有实例的轨迹到 Trace 目录"""

    if not os.path.exists(jsonl_file):
        print(f"❌ 文件不存在: {jsonl_file}")
        return

    jsonl_dir = os.path.dirname(os.path.abspath(jsonl_file))
    print(f"📂 读取文件: {jsonl_file}")
    print(f"📁 输出目录: {jsonl_dir}/Trace/\n")

    instances = []
    with open(jsonl_file, 'r') as f:
        for line in f:
            data = json.loads(line)
            instances.append(data)

    print(f"找到 {len(instances)} 个实例\n")
    print("=" * 80)

    success_count = 0
    for i, data in enumerate(instances, 1):
        instance_id = data['instance_id']
        history = data['history']

        # 创建目录结构
        trace_dir = os.path.join(jsonl_dir, 'Trace', instance_id)
        os.makedirs(trace_dir, exist_ok=True)

        # 保存轨迹
        output_file = os.path.join(trace_dir, f"{instance_id}.json")

        try:
            with open(output_file, 'w') as out:
                json.dump(history, out, indent=2)

            # 统计事件数
            event_count = len(history)
            error_status = "❌" if data.get('error') else "✓"

            print(f"[{i}/{len(instances)}] {error_status} {instance_id}")
            print(f"      事件数: {event_count}")
            print(f"      保存到: Trace/{instance_id}/{instance_id}.json")

            success_count += 1

        except Exception as e:
            print(f"[{i}/{len(instances)}] ❌ {instance_id} - 提取失败: {e}")

        print()

    print("=" * 80)
    print(f"\n✓ 完成! 成功提取 {success_count}/{len(instances)} 个实例")
    print(f"   输出目录: {jsonl_dir}/Trace/")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        print("示例:")
        print("  python extract_all_trajectories.py output.jsonl")
        print()
        print("输出结构:")
        print("  <output.jsonl所在目录>/")
        print("  └── Trace/")
        print("      ├── instance1/")
        print("      │   └── instance1.json")
        print("      ├── instance2/")
        print("      │   └── instance2.json")
        print("      └── ...")
        sys.exit(1)

    extract_all_trajectories(sys.argv[1])
