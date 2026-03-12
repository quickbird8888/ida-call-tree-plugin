
import json
import os
import sys
import datetime
import re


def save_call_tree_data(call_node_dict, call_order_list, call_tree_refs, call_tree_asm_code):
    data_to_save = {
        'call_node_dict': {},
        'call_order_list': [f"{ea:x}" for ea in call_order_list],
        'save_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    for ea, node in call_node_dict.items():
        ea_hex = f"{ea:x}"
        data_to_save['call_node_dict'][ea_hex] = {
            'name': node.name,
            'sub_call_list': [
                {
                    'ea': f"{sub_call.ea:x}",
                    'name': sub_call.name,
                    'op_ea': f"{sub_call.op_ea:x}" if sub_call.op_ea != 0 else "0",
                    'is_expand': getattr(sub_call, 'is_expand', False)
                } for sub_call in node.sub_call_list
            ]
        }
    def save_file(data_str, name, ex_name):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{name}_{timestamp}.{ex_name}'
        current_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(current_dir, 'data', filename)
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(data_str)
            print(f'[+] Saved {filepath}')
    #
    save_file(call_tree_refs,'call_tree_refs','txt')
    save_file(call_tree_asm_code,'call_tree_asm_code','txt')
    save_file(
        json.dumps(data_to_save, ensure_ascii=False, indent=2),
        'call_tree',
        'json'
    )
#