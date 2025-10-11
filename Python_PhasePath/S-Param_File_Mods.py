# -*- coding: utf-8 -*-
"""
Created on Wed Sep 17 10:53:21 2025

@author: adelgado
"""

from pathlib import Path

def split_s4p_directory(in_dir, out_dir=None):
    """
    For every .s4p in `in_dir`, write two .s2p files:
      - <stem>_p12.s2p with S11, S21, S12, S22
      - <stem>_p34.s2p with S33, S43, S34, S44
    Returns a list of (p12_path, p34_path) for the generated files.
    """
    def _strip_comment(line: str) -> str:
        return line.split('!')[0] if '!' in line else line

    def _is_option_line(line: str) -> bool:
        return line.strip().startswith('#')

    def _tokenize_numbers(s: str):
        return [tok for tok in s.strip().split() if tok]

    def _needed_tokens_per_sample(nports=4, values_per_param=2):
        return 1 + values_per_param * (nports * nports)  # freq + 2*(4*4) = 33

    def _param_token_indices(i, j, nports=4, values_per_param=2):
        # Touchstone ordering: grouped by column (j), sweeping rows (i)
        p = (j - 1) * nports + i
        start = 1 + values_per_param * (p - 1)
        end = start + values_per_param
        return start, end

    def _collect_data_lines(lines):
        for line in lines:
            raw = _strip_comment(line).rstrip()
            if not raw:
                continue
            if raw.lstrip().startswith('['):  # ignore v2 keywords like [Version]
                continue
            yield raw

    def split_s4p_file(file_path: Path, out_dir: Path):
        lines = file_path.read_text(encoding='utf-8', errors='ignore').splitlines()

        # get first option line (# ...), else default
        option_line = None
        for line in lines:
            if _is_option_line(_strip_comment(line)):
                option_line = _strip_comment(line).strip()
                break
        if option_line is None:
            option_line = "# GHZ S MA R 50"

        base = file_path.stem
        out12 = out_dir / f"{base}_p12.s2p"
        out34 = out_dir / f"{base}_p34.s2p"

        header = (f"! Auto-generated from {file_path.name}: "
                  f"{base}_p12.s2p contains S11,S21,S12,S22; "
                  f"{base}_p34.s2p contains S33,S43,S34,S44\n")

        needed = _needed_tokens_per_sample(4, 2)  # 33 tokens/sample
        buffer_tokens = []

        with out12.open('w', encoding='utf-8') as f12, out34.open('w', encoding='utf-8') as f34:
            f12.write(header); f12.write(option_line.rstrip() + "\n")
            f34.write(header); f34.write(option_line.rstrip() + "\n")

            for raw in _collect_data_lines(lines):
                if raw.strip().startswith('#'):
                    continue
                toks = _tokenize_numbers(raw)
                if not toks:
                    continue
                buffer_tokens.extend(toks)
                while len(buffer_tokens) >= needed:
                    sample = buffer_tokens[:needed]
                    buffer_tokens = buffer_tokens[needed:]

                    freq = sample[0:1]
                    # p12: S11 S21 S12 S22
                    s11 = sample[_param_token_indices(1,1)[0]:_param_token_indices(1,1)[1]]
                    s21 = sample[_param_token_indices(1,2)[0]:_param_token_indices(1,2)[1]]
                    s12 = sample[_param_token_indices(2,1)[0]:_param_token_indices(2,1)[1]]
                    s22 = sample[_param_token_indices(2,2)[0]:_param_token_indices(2,2)[1]]
                    f12.write(" ".join(freq + s11 + s21 + s12 + s22) + "\n")

                    # p34: S33 S43 S34 S44  (ports 3->1, 4->2 mapping)
                    s33 = sample[_param_token_indices(3,3)[0]:_param_token_indices(3,3)[1]]
                    s43 = sample[_param_token_indices(3,4)[0]:_param_token_indices(3,4)[1]]
                    s34 = sample[_param_token_indices(4,3)[0]:_param_token_indices(4,3)[1]]
                    s44 = sample[_param_token_indices(4,4)[0]:_param_token_indices(4,4)[1]]
                    f34.write(" ".join(freq + s33 + s43 + s34 + s44) + "\n")

        return out12, out34

    in_dir = Path(in_dir)
    out_dir = Path(out_dir) if out_dir else in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for fp in sorted(in_dir.glob("*.s4p")):
        results.append(split_s4p_file(fp, out_dir))
    return results

def main():
    split_s4p_directory(r"C:\\Users\\adelgado.LT-PF3YBWF8\\Downloads\\ADL5565_Deembedded_S_Parameters")
if __name__ == "__main__":
    main()