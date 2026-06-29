import re
import sys
import os

with open('/home/dunc/TSEC/finaltsec.md', 'r') as f:
    lines = f.readlines()

phase_names = [
    "phase01_reconnaissance",
    "phase02_attack_surface",
    "phase03_vulnerability",
    "phase04_payload",
    "phase05_privesc",
    "phase06_credentials",
    "phase07_lateral",
    "phase08_persistence",
    "phase09_objectives",
    "phase10_wireless",
]

current_phase = 0
tools_by_phase = {i: [] for i in range(1, 11)}

current_tool = None

for line in lines:
    m_phase = re.match(r'^# Phase (\d+):', line)
    if m_phase:
        current_phase = int(m_phase.group(1))
        continue
    
    m_tool = re.match(r'^## Tool (\d+)\.(\d+) — (.*)', line)
    if m_tool:
        tool_name = m_tool.group(3).strip()
        current_tool = {
            'name': tool_name,
            'description': '',
            'modes': []
        }
        if current_phase > 0 and current_phase <= 10:
            tools_by_phase[current_phase].append(current_tool)
        continue
    
    m_desc = re.match(r'^\*(.*)\*', line)
    if m_desc and current_tool and not current_tool['modes']:
        current_tool['description'] = m_desc.group(1).strip()
        continue
    
    m_row = re.match(r'^\|\s*\d+\s*\|\s*([^|]+)\s*\|\s*`([^`]+)`\s*\|\s*([^|]+)\s*\|', line)
    if m_row and current_tool:
        mode_name = m_row.group(1).strip()
        cmd = m_row.group(2).strip()
        out_type = m_row.group(3).strip()
        
        # Replace /opt/tsec/output/... with {output_file}
        cmd = re.sub(r'/opt/tsec/output/[^\s"`|]+', '{output_file}', cmd)
        
        # Find inputs
        placeholders = re.findall(r'\{([a-zA-Z0-9_]+)\}', cmd)
        inputs = []
        for ph in placeholders:
            if ph == 'output_file': continue
            
            # Map ph to InputKind
            if ph in ['domain', 'domain_list', 'domain_list_file', 'wildcard_domain']: ik = 'InputKind::Domain'
            elif ph in ['ip', 'cidr', 'ip_list', 'host_list']: ik = 'InputKind::Ip'
            elif ph in ['url', 'url_list', 'target_url']: ik = 'InputKind::Url'
            elif ph in ['target', 'target1', 'target2', 'target3']: ik = 'InputKind::Target'
            elif ph in ['user', 'username', 'user1', 'user2', 'user3']: ik = 'InputKind::Username'
            elif ph in ['password', 'pass']: ik = 'InputKind::Password'
            elif ph in ['interface', 'iface']: ik = 'InputKind::Interface'
            elif ph in ['hash', 'ntlm_hash']: ik = 'InputKind::Hash'
            elif ph in ['wordlist', 'wordlist1', 'wordlist2']: ik = 'InputKind::Wordlist'
            elif ph in ['payload', 'shellcode']: ik = 'InputKind::Payload'
            elif ph in ['session']: ik = 'InputKind::Session'
            elif ph in ['lhost']: ik = 'InputKind::Lhost'
            elif ph in ['lport']: ik = 'InputKind::Lport'
            elif ph in ['ports', 'port']: ik = 'InputKind::Ports'
            elif ph in ['file', 'capture', 'mac_file', 'config_file', 'config', 'cert_file', 'key_file', 'precomputed']: ik = 'InputKind::File'
            else:
                label = ph.replace('_', ' ').title()
                ik = f'InputKind::Custom("{label}", "{ph}")'
            
            if ik not in inputs:
                inputs.append(ik)
        
        # Determine output format and file ext
        out_type = out_type.split('/')[0].strip() # HTML/XML -> HTML
        
        if out_type == 'TXT': 
            out_fmt = 'OutputFormat::Lines'
            ext = 'txt'
        elif out_type == 'JSON':
            out_fmt = 'OutputFormat::Json'
            ext = 'json'
        elif out_type == 'HTML':
            out_fmt = 'OutputFormat::Raw'
            ext = 'html'
        elif out_type == 'XML':
            out_fmt = 'OutputFormat::Xml'
            ext = 'xml'
        elif out_type == 'CSV':
            out_fmt = 'OutputFormat::Csv'
            ext = 'csv'
        elif out_type == 'NMAP':
            out_fmt = 'OutputFormat::Nmap'
            ext = 'nmap'
        elif out_type in ['ALL', 'RAW', 'BIN']:
            out_fmt = 'OutputFormat::Raw'
            ext = 'raw'
        elif out_type == 'LIST':
            out_fmt = 'OutputFormat::Lines'
            ext = 'list'
        elif out_type == 'BROWSER':
            out_fmt = 'OutputFormat::Raw'
            ext = 'html'
        elif out_type == 'LOG':
            out_fmt = 'OutputFormat::Lines'
            ext = 'log'
        elif out_type == 'DB':
            out_fmt = 'OutputFormat::Raw'
            ext = 'db'
        elif out_type == 'PCAPNG':
            out_fmt = 'OutputFormat::Raw'
            ext = 'pcapng'
        elif out_type == 'PNG':
            out_fmt = 'OutputFormat::Raw'
            ext = 'png'
        elif out_type == '22000':
            out_fmt = 'OutputFormat::Raw'
            ext = '22000'
        else:
            out_fmt = 'OutputFormat::Raw'
            ext = 'out'
            
        current_tool['modes'].append({
            'name': mode_name,
            'cmd': cmd,
            'inputs': inputs,
            'out_fmt': out_fmt,
            'ext': ext
        })

# Now write the files
out_dir = '/home/dunc/TSEC/src/tools'
for phase, tools in tools_by_phase.items():
    if not tools: continue
    
    file_name = f'{out_dir}/{phase_names[phase-1]}.rs'
    with open(file_name, 'w') as f:
        f.write('use crate::tools::types::{Tool, Mode, InputKind, OutputFormat};\n\n')
        f.write('pub const TOOLS: &[Tool] = &[\n')
        
        for tool in tools:
            # Figure out binary name
            binary_name = tool['name'].split()[0].lower()
            if tool['modes']:
                # handle "python3 something"
                first_word = tool['modes'][0]['cmd'].split()[0]
                if first_word in ['python3', 'python', 'bash', 'sh', 'perl', 'ruby']:
                    binary_name = tool['modes'][0]['cmd'].split()[1].split('/')[-1]
                else:
                    binary_name = first_word
                # handle 'sed' in some commands like 'sed -i ... && hostapd-wpe'
                if binary_name == 'sed' and '&&' in tool['modes'][0]['cmd']:
                    binary_name = tool['modes'][0]['cmd'].split('&&')[1].strip().split()[0]
            
            # Sanitize binary_name if it has quotes or weird chars
            binary_name = binary_name.replace('"', '').replace("'", "")
            
            f.write('    Tool {\n')
            f.write(f'        name: "{tool["name"]}",\n')
            f.write(f'        binary: "{binary_name}",\n')
            f.write(f'        description: "{tool["description"]}",\n')
            f.write('        modes: &[\n')
            
            for mode in tool['modes']:
                cmd_raw = mode['cmd']
                # If cmd contains "#", it could conflict with r#"..."#. We'll use r##"..."## if needed.
                hash_count = cmd_raw.count('"#')
                if hash_count > 0:
                    raw_wrapper = 'r##"{}"##'
                else:
                    raw_wrapper = 'r#"{}"#'
                
                cmd_escaped = raw_wrapper.format(cmd_raw)
                
                f.write('            Mode {\n')
                f.write(f'                name: "{mode["name"]}",\n')
                f.write(f'                cmd_template: {cmd_escaped},\n')
                f.write(f'                inputs: &[{", ".join(mode["inputs"])}],\n')
                f.write(f'                output_format: {mode["out_fmt"]},\n')
                f.write(f'                file_ext: "{mode["ext"]}",\n')
                f.write('            },\n')
                
            f.write('        ],\n')
            f.write('    },\n')
            
        f.write('];\n')

print("Done generating 10 phase files.")
