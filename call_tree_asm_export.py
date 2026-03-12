"""
Recursively export assembly code and call relationships of the entire call tree
"""
import idaapi
import idc
import idautils
import ida_kernwin
import sys
import threading
import time
import os
import json
from my_scripts.call_tree_save import save_call_tree_data


g_plugin_name = "Recursive Copy Assembly Code"

def debug_log(msg):
    """Write debug log"""
    print(msg)
    g_debug_file = os.path.join(os.path.dirname(__file__), "my_scripts", "log", "debug.log")
    with open(g_debug_file, 'a', encoding='utf-8') as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")

class LibInfo:
    arch = ''
    code_seg_range = [0, 0]
    @staticmethod
    def get_arch_type():
        proc_name = idaapi.inf_get_procname().lower()
        is_64bit = idaapi.inf_is_64bit()
        if 'arm' in proc_name:
            return 'arm64' if is_64bit else 'arm'
        elif 'metapc' in proc_name:
            return 'x64' if is_64bit else 'x86'
        else:
            return 'unknown'       
    #
    @staticmethod
    def init():
        if __class__.arch != '':
            return
        __class__.arch =  __class__.get_arch_type()
        for seg in idautils.Segments():
            seg_name = idc.get_segm_name(seg)
            if seg_name in ['.text', '.code', 'CODE']:  # code segment
                seg_info = idaapi.getseg(seg)
                __class__.code_seg_range[0] = seg
                __class__.code_seg_range[1] = seg + seg_info.size()
    #
    @staticmethod    
    def get_arch():
        return __class__.arch
    #
    @staticmethod    
    def get_code_seg_range():
        return  __class__.code_seg_range
    #
    @staticmethod    
    def is_of_code_seg(ea):
        start, end = __class__.code_seg_range
        return start <= ea <= end 
    #
#
class InsnStruct:
    def __init__(self,ea):
        self.is_call = False
        self.is_expand = False
        self.ea = ea
        self.name = ''
        self.op_ea = 0
        self.asm_code = ''
    #
    def get_asm_code(self):
        return self.asm_code
    #
    def fmt_asm_code(self, lable, code):
        self.asm_code = f'{self.ea:x}  {lable:<16}{code}'
    #    
#
class CallListObjStruct:
    def __init__(self, ea, name, op_ea, is_expand):
        self.ea = ea
        self.name = name
        self.op_ea = op_ea
        self.is_expand = is_expand
    #
#
class CallParser():
    filters = None
    def __init__(self, ea):
        self.ea = ea
        self.end_ea = 0
        self.name = ''
        self.sub_call_list = []
        self.asm_code_list = []
        self.asm_code_out = ''
        self.call_tree_refs_out = ''
        self.type = 'normal'
        self.ref_count = 0
        self.eas = []
        self.parse()
    #
    def inst_parse(self, ea):    
        def get_simplify_name(asm_code):
            ams_str = asm_code.strip().split(';')[0].rstrip()
            return ' '.join(ams_str.split())
        #
        arch = LibInfo.get_arch()
        inst_obj = InsnStruct(ea)
        mnem = idc.print_insn_mnem(ea).lower()
        asm_code_tmp = idc.generate_disasm_line(ea, 0).lower()
        lable = idc.get_name(ea).lower()
        if arch in ['x86','x64'] and mnem in ['call','jmp']:
            op_type = idc.get_operand_type(ea, 0)
            old_target = idc.get_operand_value(ea, 0)
            target = old_target
            if op_type in [idc.o_reg, idc.o_phrase, idc.o_displ]: # handle register indirect calls
                inst_obj.is_call = True
                inst_obj.name = get_simplify_name(asm_code_tmp)
            elif op_type in [idc.o_mem, idc.o_near]: # handle memory indirect calls and direct calls
                if op_type == idc.o_mem:
                    target = idaapi.get_qword(target) if arch == 'x64' else idaapi.get_dword(target)
                func_type = self.func_check(target)
                if func_type == 'func':
                    inst_obj.is_expand = True; inst_obj.op_ea = target; inst_obj.is_call = True
                    asm_code_tmp = f'{mnem:<8}sub_{target:x}'
                elif func_type == 'api':#api call memcpy
                    inst_obj.is_expand = False; inst_obj.op_ea = target; inst_obj.is_call = True
                else:
                    if mnem == 'jmp' and old_target != target and target in self.eas:
                        asm_code_tmp = f'{mnem:<8}{target:x}'
                inst_obj.name = self.fmt_call_name(target, mnem)
            else: #idc.o_far
                # unknown instruction type
                inst_obj.is_call = True
                inst_obj.name = self.fmt_call_name(target, mnem)
            #
        #
        elif arch in ['arm', 'arm64'] and  mnem in ['bl', 'br', 'blr', 'bx', 'b']:
            target = idc.get_operand_value(ea, 0)         
            if mnem in ['bl', 'b']:
                func_type = self.func_check(target, mnem)
                if func_type == 'func':
                    inst_obj.is_expand = True; inst_obj.op_ea = target; inst_obj.is_call = True
                    asm_code_tmp = f'{mnem:<16}sub_{target:x}'
                elif func_type == 'api':
                    inst_obj.is_expand = False; inst_obj.op_ea = target; inst_obj.is_call = True
                inst_obj.name = self.fmt_call_name(target, mnem)
            else:
                inst_obj.is_call = True
                inst_obj.name = get_simplify_name(asm_code_tmp)
            #               
        #
        inst_obj.fmt_asm_code(lable, asm_code_tmp)
        
        # If it's a call instruction, check if target address needs filtering
        if inst_obj.is_call and inst_obj.op_ea in __class__.filters:
            inst_obj.name = __class__.filters[inst_obj.op_ea]
            debug_log(f"[CallParser.inst_parse] filtered call target: {inst_obj.op_ea:x} -> {inst_obj.name}")
        
        return inst_obj
    #
    def is_in_func(self, ea):
        return ea in self.eas
        # return self.ea <= ea <= self.end_ea
    #
    def func_check(self, ea, mnem = None):
        if not self.eas:
            return 'error'
        if ea and not LibInfo.is_of_code_seg(ea):
            return 'api'
        if ea and mnem and mnem == 'b' and  ea == self.end_ea:
            return 'normal'
        if not ea or not idaapi.get_func(ea) or ea in self.eas:
            return 'normal'
        return 'func'
    #
    def parse(self):
        self.load_call_filters()
        if not idaapi.get_func(self.ea):
            return
        self.type = 'call'
        self.name = self.fmt_call_name(self.ea)
        self.eas = list(idautils.FuncItems(self.ea))
        if self.eas:
            self.end_ea = self.eas[-1]  
        else:
           debug_log(f"[CallParser.parse] build eas is null: {self.ea:x}")
           return
        for ea in self.eas:
            inst_obj = self.inst_parse(ea)
            if inst_obj.is_call:
                self.sub_call_list.append(CallListObjStruct(ea, inst_obj.name, inst_obj.op_ea, inst_obj.is_expand))
            self.asm_code_list.append(inst_obj.asm_code)
        self.fmt_out()
    #
    def load_call_filters(self):
        """Load call filter configuration"""
        if __class__.filters:  # check if dictionary has content
            return
        __class__.filters = {}
        filter_file = os.path.join(os.path.dirname(__file__), "my_scripts", "call_filters.json")
        if os.path.exists(filter_file):
            with open(filter_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    ea = int(item['ea'], 16)  # convert hex string to integer
                    alias = item['alias']
                    __class__.filters[ea] = alias
            debug_log(f"[CallParser.load_call_filters] loaded {len(__class__.filters)} filters")
    #
    def is_symbol_name(self, name):
        if name.startswith('sub_'):
            return False
        return True
    #
    def fmt_call_name(self, ea, mnem = None):
        if not ea:
            return 'sub_reg'
        ret = f'sub'
        func_name = idc.get_func_name(ea)
        if func_name and self.is_symbol_name(func_name):
            # Remove all leading . and _
            while func_name and func_name[0] in ['.', '_']:
                func_name = func_name[1:]
        else:
            func_name = ''
        if LibInfo.is_of_code_seg(ea):
            ret += f'_{ea:x}'
            if func_name != '':
                ret += f'_{func_name}'
        else:
            if func_name != '':
                if mnem:
                    ret = f'{mnem} {func_name}'
                else:
                    ret += f'_{func_name}'
            else:
                ret += '_unknown'
        return ret
    #        
    def fmt_out(self):
        self.fmt_call_tree_refs_out()
        self.fmt_asm_code_out()
    #
    def fmt_asm_code_out(self):
        self.asm_code_out = f'{self.name}()\n'
        for insn_str in self.asm_code_list:
            self.asm_code_out += f'    {insn_str}\n'
        self.asm_code_out += f'{self.name} end\n'
    #
    def fmt_call_tree_refs_out(self):
        self.call_tree_refs_out = f'{self.name}()\n'
        for sub_call in self.sub_call_list:
            self.call_tree_refs_out += f'    {sub_call.name}\n'
        self.call_tree_refs_out += f'{self.name} end\n'
    #    
    def get_sub_count(self):
        return len(self.sub_call_list)
    #
    def get_subs(self):
        return self.sub_call_list
    #
    def add_ref_count(self):
        self.ref_count += 1
    #
    def get_asm_code_out(self):
        return self.asm_code_out
    #
    def get_call_tree_refs_out(self):
        return self.call_tree_refs_out
    #    
#
class RecursiveCallTreeAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.call_node_dict = {}  # call tree node dictionary
        self.call_order_list = []  # call order list
        self.windows = None
    #
    def build_call_tree(self, start_ea):
        def build_subtree(ea):
            if ea in self.call_node_dict:  # already processed indicates loop
                node = self.call_node_dict[ea]
                node.add_ref_count()
                return None
            node = CallParser(ea)
            if node.type == 'normal':
                return None
            node.add_ref_count()
            self.call_node_dict[ea] = node
            self.call_order_list.append(ea)
            for sub_node in node.get_subs():
                if sub_node.is_expand:
                    build_subtree(sub_node.op_ea)
            return node
        #
        build_subtree(start_ea)
    #
    def  get_call_tree_asm_code(self):
        if not self.call_node_dict:
            return
        out = ''
        for ea in self.call_order_list:
            node = self.call_node_dict[ea]
            out += node.get_asm_code_out() + '\n'
        return out
    #
    def get_call_tree_refs(self):
        if not self.call_node_dict:
            return
        out = ''        
        for ea in self.call_order_list:
            node = self.call_node_dict[ea]
            out += node.get_call_tree_refs_out() + '\n'
        return out
    #
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    #
    def show_call_tree_window(self):   
        save_call_tree_data(self.call_node_dict, self.call_order_list, self.get_call_tree_refs(), self.get_call_tree_asm_code())
    #
    def my_callback(self, start_ea):
        # Initialize LibInfo in main thread
        LibInfo.init()
        self.call_node_dict.clear()
        self.call_order_list = []
        debug_log('Start recursive call tree traversal...')
        self.build_call_tree(start_ea)     
        if self.call_node_dict:
            debug_log(f'Call tree construction completed, total {len(self.call_node_dict)} nodes')
        self.show_call_tree_window()
    #
    def activate(self, ctx):
        """Start call tree analysis entry"""
        start_ea = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
        if start_ea == idc.BADADDR:
            debug_log('Please place cursor inside function')
            return 0
        debug_log(f'Current address: {start_ea:x}')
        self.my_callback(start_ea)
        return 1    
#
class RecursiveCallTreePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Recursive Call Tree Export"
    help = "Recursively export entire call tree assembly code"
    wanted_name = "RecursiveCallTree"
    wanted_hotkey = ""
    def init(self):
        print("\n[Initialize recursive call tree plugin]")
        
        # Try to unregister existing actions first
        try:
            idaapi.unregister_action('recursive:calltree')
            print("[+] Clean up old action registration")
        except:
            pass
        
        # Register action
        action_desc = idaapi.action_desc_t('recursive:calltree','🌲 Recursive Call Tree Export',RecursiveCallTreeAction(),'','Recursively export current function and all its sub-functions assembly code and call relationships',165 )
        # Register action
        if not idaapi.register_action(action_desc):
            print("[-] Failed to register action")
            return idaapi.PLUGIN_SKIP
        print("[+] Recursive call tree action registration successful")
        print("[+] Usage: Right click at function start -> Recursive Export Call Tree")
        # Install right-click menu hook
        self.install_popup_hook()
        return idaapi.PLUGIN_KEEP
    #
    def install_popup_hook(self):
        """Install right-click menu hook"""
        class PopupHook(idaapi.UI_Hooks):
            def finish_populating_widget_popup(self, widget, popup):
                if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
                    # Add to right-click menu
                    idaapi.attach_action_to_popup(widget, popup, 'recursive:calltree', None)
        # Store hook for cleanup
        if not hasattr(self, 'popup_hook'):
            self.popup_hook = PopupHook()
            self.popup_hook.hook()
    #
    def run(self, arg):
        pass
    #
    def term(self):
        """Clean up hooks and actions when plugin is unloaded"""
        try:
            idaapi.unregister_action('recursive:calltree')
            print("[+] Recursive call tree action has been unregistered")
        except:
            pass
        if hasattr(self, 'popup_hook'):
            try:
                self.popup_hook.unhook()
            except:
                pass
    #
#
def PLUGIN_ENTRY():
    return RecursiveCallTreePlugin()
#