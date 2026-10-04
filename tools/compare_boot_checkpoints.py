"""Compare paired instruction-boundary evidence without claiming timing parity."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('retail', type=Path)
parser.add_argument('native_log', type=Path)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
retail = json.loads(args.retail.read_text(encoding='utf-8-sig'))
native = {}
for line in args.native_log.read_text(encoding='utf-8', errors='replace').splitlines():
    if line.startswith('[PARITY] '):
        row = json.loads(line[len('[PARITY] '):])
        native[row['name']] = row

def ring(words):
    if not words or len(words) < 11:
        return None
    values = [int(x, 16) if x is not None else None for x in words]
    if any(values[i] is None for i in (0, 1, 9, 10)):
        return {'error': 'unreadable field'}
    return {'put': words[0], 'current_block_end': words[1],
            'allocation_base': words[9], 'allocation_end': words[10],
            'allocation_bytes': values[10] - values[9],
            'put_offset': values[0] - values[9],
            'block_end_offset': values[1] - values[9]}

result = {'schema': 'dah2-boot-comparison-v1',
          'retail': str(args.retail.resolve()), 'native_log': str(args.native_log.resolve()),
          'timing_parity_verified': False,
          'note': 'Matching checkpoint addresses align observations. Different allocation/stack addresses are expected from distinct runtimes. Breakpoints and logging perturb wall-clock timing.',
          'checkpoints': []}
for ref in retail['checkpoints']:
    name = ref['name']
    cur = native.get(name)
    item = {'name': name, 'retail_hit': ref.get('hit'), 'native_captured': cur is not None}
    if cur:
        item['same_instruction_boundary'] = cur['address'].lower() == ref['address'].lower()
        item['retail_ring'] = ring(ref.get('device_head', {}).get('u32_le'))
        item['native_ring'] = ring(cur.get('device_head'))
        item['input_globals'] = {
            key: {'retail': ref.get('comparison_globals', {}).get(key, {}).get('u32_le', [None])[0],
                  'native': values[0] if values else None}
            for key, values in cur.get('input_globals', {}).items()}
        rp = ref.get('push_buffer_prefix', {}).get('u32_le')
        np = cur.get('push_buffer_prefix')
        if rp and np and item['retail_ring'] and item['native_ring']:
            limit = min(len(rp), len(np), item['retail_ring']['put_offset'] // 4,
                        item['native_ring']['put_offset'] // 4)
            differences = [{'offset': hex(i * 4), 'retail': a, 'native': b}
                           for i, (a, b) in enumerate(zip(rp[:limit], np[:limit])) if a != b]
            item['push_buffer_prefix_comparison'] = {
                'note': 'Raw words; runtime-dependent addresses are not normalized.',
                'compared_words': limit, 'different_words': len(differences),
                'first_differences': differences[:16]}
        if name == 'create_device':
            rp = ref.get('presentation_parameters', {}).get('u32_le')
            np = cur.get('presentation_parameters')
            item['presentation_parameters_equal'] = rp is not None and rp == np
            item['presentation_parameters_differences'] = [
                {'offset': hex(i * 4), 'retail': a, 'native': b}
                for i, (a, b) in enumerate(zip(rp or [], np or [])) if a != b]
        rr = ref['registers']['i386']
        item['register_differences'] = {key: {'retail': rr.get(key), 'native': value}
                                      for key, value in cur['registers'].items() if value != rr.get(key)}
    result['checkpoints'].append(item)
if args.output:
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
print(json.dumps(result, indent=2))
