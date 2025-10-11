import skrf as rf
import pandas as pd
import numpy as np
import os
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize, BoundaryNorm, ListedColormap
from matplotlib.cm import get_cmap
import seaborn as sns

def process_s2p_data(s2p_files, freq_sweeps,
                     absolute_threshold_db=None,
                     absolute_threshold_direction='falling',
                     custom_data_df=None,
                     include_passband_start=False):
    """
    Reads all S2P files once, extracts S21 data for different frequency sweeps,
    calculates metrics, merges optional custom data, and returns a dictionary of DataFrames.
    """
    if isinstance(s2p_files, (str, Path)):
        directory = Path(s2p_files)
        s2p_files = list(directory.glob('*.s2p')) + list(directory.glob('*.S2P'))
    
    if not s2p_files:
        raise ValueError("No S2P files found in the specified directory.")

    data_results = {key: {} for key in freq_sweeps}
    cutoff_frequencies = {}
    passband_start_frequencies = {}   # NEW
    threshold_frequencies = {}

    def find_threshold_frequency(network, level, relative_to_max, selection, direction):
        """Finds a frequency based on a dB level crossing in a specific direction."""
        try:
            freq_fine = np.linspace(network.f[0], network.f[-1], 2001)
            net_fine = network.interpolate(rf.Frequency.from_f(freq_fine, unit='Hz'))
            s21_db_fine = net_fine.s21.s_db[:,0,0]
            
            target_level = np.max(s21_db_fine) + level if relative_to_max else level
            
            crossings = []
            for i in range(len(s21_db_fine) - 1):
                f1, f2 = freq_fine[i], freq_fine[i+1]; s1, s2 = s21_db_fine[i], s21_db_fine[i+1]
                if direction == 'falling' and s1 >= target_level and s2 < target_level:
                    crossings.append(f1 + (target_level - s1) * (f2 - f1) / (s2 - s1))
                elif direction == 'rising' and s1 <= target_level and s2 > target_level:
                    crossings.append(f1 + (target_level - s1) * (f2 - f1) / (s2 - s1))
            
            if not crossings:
                return f"> {network.f[-1]/1e9:.1f}" if np.all(s21_db_fine >= target_level) else "N/A"
            return (max(crossings) if selection == 'max' else min(crossings)) / 1e9
        except Exception:
            return "N/A"

    for file_path in s2p_files:
        try:
            network = rf.Network(file_path); filename = Path(file_path).stem
            # End of passband (-3 dB falling)
            cutoff_frequencies[filename] = find_threshold_frequency(network, -3, True, 'max', 'falling')
            # Start of passband (-3 dB rising)
            if include_passband_start:
                passband_start_frequencies[filename] = find_threshold_frequency(network, -3, True, 'min', 'rising')

            if absolute_threshold_db is not None:
                threshold_frequencies[filename] = find_threshold_frequency(network, absolute_threshold_db, False, 'min', absolute_threshold_direction)

            for key, frequencies in freq_sweeps.items():
                result_array = np.full(len(frequencies), np.nan)
                net_min_f, net_max_f = network.f[0], network.f[-1]
                valid_mask = (frequencies >= net_min_f) & (frequencies <= net_max_f)
                interp_freqs = frequencies[valid_mask]

                if interp_freqs.size > 0:
                    net_interp = network.interpolate(rf.Frequency.from_f(interp_freqs, unit='Hz'))
                    if key in ['table', 'mag']: interpolated_data = net_interp.s21.s_db[:,0,0]
                    elif key == 'phase': interpolated_data = net_interp.s21.s_deg_unwrap[:,0,0]
                    elif key == 'gd': interpolated_data = net_interp.s21.group_delay[:,0,0] * 1e9
                    result_array[valid_mask] = interpolated_data
                data_results[key][filename] = result_array
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            for key in freq_sweeps: data_results[key][filename] = np.full(len(freq_sweeps[key]), np.nan)
            cutoff_frequencies[filename] = "Error"; passband_start_frequencies[filename] = "Error"; threshold_frequencies[filename] = "Error"
    
    final_dfs = {}
    for key, results_dict in data_results.items():
        freq_labels = [f"{f/1e9:.3f} GHz" for f in freq_sweeps[key]]
        df = pd.DataFrame(results_dict, index=freq_labels).T
        if key == 'table':
            if include_passband_start:
                df['Passband_Start_-3dB_GHz'] = pd.Series(passband_start_frequencies)  # NEW
            df['Cutoff_-3dB_GHz'] = pd.Series(cutoff_frequencies)
            if absolute_threshold_db is not None:
                df[f"Freq_at_{absolute_threshold_db}dB_GHz"] = pd.Series(threshold_frequencies)
            if custom_data_df is not None:
                df = df.join(custom_data_df)
        final_dfs[key] = df
    return final_dfs

def create_matplotlib_table(df, filename="s21_summary_table.png", title="S21 Performance Summary", cmap_name='viridis', color_ranges=None, freq_descriptions=None, strict_range=False):
    """Creates a styled table with auto-adjusting header placement."""
    print(f"Creating Matplotlib table and saving as '{filename}'...")
    df_plot = df.copy()
    
    df_plot = df_plot.copy()

    for col in df_plot.columns:
        df_plot[col] = pd.to_numeric(df_plot[col], errors='coerce')
        if pd.api.types.is_numeric_dtype(df_plot[col]):
            df_plot[col] = df_plot[col].round(2).astype(str)
        else:
            df_plot[col] = df_plot[col].astype(str)



    if freq_descriptions:
        desc_series = pd.Series({col: freq_descriptions.get(col, '') for col in df_plot.columns}, name='Description')
        df_plot = pd.concat([desc_series.to_frame().T, df_plot])

    known_metric_prefixes = ('Cutoff', 'Freq_at', 'Passband_Start')
    s21_columns = [c for c in df.columns if 'GHz' in c and not c.startswith(known_metric_prefixes)]
    
    cmap = get_cmap(cmap_name); final_ranges = {}
    for col in s21_columns:
    # Check if user provided manual range
        if color_ranges and col in color_ranges:
            final_ranges[col] = color_ranges[col]
        else:
            # Auto-scale if not provided
            min_val, max_val = pd.to_numeric(df[col], errors='coerce').min(), pd.to_numeric(df[col], errors='coerce').max()
            if pd.isna(min_val) or min_val == max_val:
                min_val, max_val = (-10, 0) if pd.isna(min_val) else (min_val - 0.5, max_val + 0.5)
            final_ranges[col] = {"vmin": min_val, "vmax": max_val}

    fig, ax = plt.subplots(facecolor='#333333'); ax.axis('off')
    
    table = ax.table(
        cellText=df_plot.values, colLabels=df_plot.columns, rowLabels=df_plot.index,
        loc='center', cellLoc='center'
    )
    table.auto_set_font_size(False); table.set_fontsize(12)
    table.auto_set_column_width(col=list(range(len(df_plot.columns))))
    table.scale(1.2, 1.8)

    base_cell_height = 0.08
    for i, row in enumerate(df_plot.iterrows()):
        max_lines = row[1].astype(str).str.count('\n').max() + 1
        cell_height = base_cell_height * max_lines
        for j in range(-1, len(df_plot.columns)):
            table[(i + 1, j)].set_height(cell_height)

    for (i, j), cell in table.get_celld().items():
        cell.set_edgecolor('#555555'); cell.set_linewidth(1.0)
        cell.set_text_props(va='center')
        if i == 0 or j == -1:
            cell.set_facecolor("#555555"); cell.set_text_props(color='white', weight='bold', va='center')
        else:
            row_label, col_label = df_plot.index[i-1], df_plot.columns[j]
            if freq_descriptions and row_label == 'Description':
                cell.set_facecolor('#404040'); cell.set_text_props(color='white', weight='bold', style='italic', va='center'); continue
            if col_label in s21_columns:
                val = pd.to_numeric(df_plot.iloc[i-1, j], errors='coerce')
                if pd.notna(val):
                    vmin = final_ranges[col_label]["vmin"]
                    vmax = final_ranges[col_label]["vmax"]
                    
                    if strict_range:  # optional toggle per analysis case
                        cmap = ListedColormap(["red", "green", "red"])
                        bounds = [float("-inf"), vmin, vmax, float("inf")]
                        norm = BoundaryNorm(bounds, cmap.N)
                    else:
                        norm = Normalize(vmin=vmin, vmax=vmax)
                    
                    cell.set_facecolor(cmap(norm(val)))
                    cell.set_text_props(color='white', va='center')
                else: cell.set_facecolor('#444444'); cell.set_text_props(color='lightgrey', va='center')
            else: cell.set_facecolor('#4a6e8a'); cell.set_text_props(color='white', va='center')
    
    # --- AUTO-ADJUST TITLE ---
    fig.canvas.draw()
    table_bbox = table.get_window_extent(fig.canvas.get_renderer())
    ax_bbox = ax.get_window_extent(fig.canvas.get_renderer())
    table_top = (table_bbox.y1 - ax_bbox.y0) / ax_bbox.height
    ax.text(0.5, table_top + 0.05, title, transform=ax.transAxes, ha='center', va='bottom',
            fontsize=18, weight='bold', color='white')
    
    try:
        plt.savefig(filename, dpi=200, bbox_inches='tight', pad_inches=0.2, facecolor=fig.get_facecolor())
        print(f"✅ Successfully saved styled table to '{filename}'")
    except Exception as e: print(f"❌ Error saving table image: {e}")
    finally: plt.close(fig)

def plot_s21_curves(df, title="S21 Transmission vs. Frequency", filename="s21_mag_plot.png", xlim_min=None, xlim_max=None):
    """Generates and saves a line plot of S21 magnitude data."""
    print(f"Creating S21 magnitude plot and saving as '{filename}'...")
    sns.set_theme(style="whitegrid"); plt.figure(figsize=(12, 7))
    frequencies_ghz = [float(col.split()[0]) for col in df.columns]
    for device_name, s21_values in df.iterrows(): plt.plot(frequencies_ghz, s21_values, label=device_name)
    plt.title(title, fontsize=16, weight='bold'); plt.xlabel("Frequency (GHz)", fontsize=12)
    plt.ylabel("S21 Magnitude (dB)", fontsize=12); plt.legend(title="Device", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.axhline(-3, color='red', linestyle='--', linewidth=1.5); plt.ylim(df.min().min() - 5, df.max().max() + 5)
    plt.grid(True, which='both', linestyle='--')
    if xlim_min is not None or xlim_max is not None: plt.xlim(xlim_min, xlim_max)
    plt.tight_layout(rect=[0, 0, 0.85, 1])
    try:
        plt.savefig(filename, dpi=300, bbox_inches='tight'); print(f"✅ Successfully saved magnitude plot to '{filename}'")
    except Exception as e: print(f"❌ Error saving plot: {e}")
    finally: plt.close()

def plot_s21_phase_curves(df, title="S21 Phase vs. Frequency", filename="s21_phase_plot.png", xlim_min=None, xlim_max=None):
    """Generates and saves a line plot of S21 phase data."""
    print(f"Creating S21 phase plot and saving as '{filename}'...")
    sns.set_theme(style="whitegrid"); plt.figure(figsize=(12, 7))
    frequencies_ghz = [float(col.split()[0]) for col in df.columns]
    for device_name, s21_values in df.iterrows(): plt.plot(frequencies_ghz, s21_values, label=device_name)
    plt.title(title, fontsize=16, weight='bold'); plt.xlabel("Frequency (GHz)", fontsize=12)
    plt.ylabel("S21 Phase (Degrees)", fontsize=12); plt.legend(title="Device", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, which='both', linestyle='--')
    if xlim_min is not None or xlim_max is not None: plt.xlim(xlim_min, xlim_max)
    plt.tight_layout(rect=[0, 0, 0.85, 1])
    try:
        plt.savefig(filename, dpi=300, bbox_inches='tight'); print(f"✅ Successfully saved phase plot to '{filename}'")
    except Exception as e: print(f"❌ Error saving phase plot: {e}")
    finally: plt.close()

def plot_group_delay_curves(df, title="Group Delay vs. Frequency", filename="s21_gd_plot.png", xlim_min=None, xlim_max=None):
    """Generates and saves a line plot of S21 group delay."""
    print(f"Creating group delay plot and saving as '{filename}'...")
    sns.set_theme(style="whitegrid"); plt.figure(figsize=(12, 7))
    frequencies_ghz = [float(col.split()[0]) for col in df.columns]
    for device_name, gd_values in df.iterrows(): plt.plot(frequencies_ghz, gd_values, label=device_name)
    plt.title(title, fontsize=16, weight='bold'); plt.xlabel("Frequency (GHz)", fontsize=12)
    plt.ylabel("Group Delay (ns)", fontsize=12); plt.legend(title="Device", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, which='both', linestyle='--'); plt.ylim(bottom=0)
    if xlim_min is not None or xlim_max is not None: plt.xlim(xlim_min, xlim_max)
    plt.tight_layout(rect=[0, 0, 0.85, 1])
    try:
        plt.savefig(filename, dpi=300, bbox_inches='tight'); print(f"✅ Successfully saved group delay plot to '{filename}'")
    except Exception as e: print(f"❌ Error saving group delay plot: {e}")
    finally: plt.close()

# --------------------------------------------------------------------------
# --- MAIN EXECUTION BLOCK ---
# --------------------------------------------------------------------------
def main():
    """Main function to run one or more S-parameter analyses."""
    
    amp_custom_data = pd.DataFrame({
        'OP1dB': {
            'ADL8102ACPZN_+25degC' : '13.5dBm Typ',
            'CMD283_SS_Vdd=3p0_Vgg=1p5': '14dBm @ 3.5GHz\n11.5dBm @ 5GHz',
            'cmd283c3-sparameters': '16dBm Typ',
            'cmd308_sparameters' : '12.5-13dBm Typ',
            'cmd308p4_sparameters': '12.5-13dBm Typ',
            'GRF2176_DC2347_HGM_Vdd5V_60mA': '19.6dBm Typ',
            'PMA3-63GLN+_5.00V_Plus25DegC_Unit1': '14dBm @ 3.5GHz\n11.5dBm @ 5GHz',
            'QPA9120-s-parameter': '22dBm @ 3.5GHz\n21dBm @ 4.8GHz'
        }
    })
    
    CBRS_BPF_custom_data = pd.DataFrame({
        'OP1dB': {
            'ADL8102ACPZN_+25degC' : '13.5dBm Typ',
            'CMD283_SS_Vdd=3p0_Vgg=1p5': '14dBm @ 3.5GHz\n11.5dBm @ 5GHz',
            'cmd283c3-sparameters': '16dBm Typ',
            'cmd308_sparameters' : '12.5-13dBm Typ',
            'cmd308p4_sparameters': '12.5-13dBm Typ',
            'GRF2176_DC2347_HGM_Vdd5V_60mA': '19.6dBm Typ',
            'PMA3-63GLN+_5.00V_Plus25DegC_Unit1': '14dBm @ 3.5GHz\n11.5dBm @ 5GHz',
            'QPA9120-s-parameter': '22dBm @ 3.5GHz\n21dBm @ 4.8GHz'
        }
    })
    
    analysis_cases = {
        "Single_Amp_Analysis": {
            "description": "Analysis of Single Amps",
            "s2p_directory": "C:\\Users\\adelgado.LT-PF3YBWF8\\Documents\\Design Files\\Phase Path board\\S2P Files\\SingleAmpOptions",
            "absolute_threshold_db": 15,
            "absolute_threshold_direction": 'rising',
            "custom_data": amp_custom_data,
            "frequency_sweeps": {
                'table': np.array([800e6, 1.580e9, 3.625e9, 4.25e9, 5e9, 6.796e9, 7.816e9]),
                'mag':   np.linspace(1e9, 9e9, 201),
                'phase': np.linspace(1e9, 6e9, 201),
                'gd':    np.linspace(1e9, 6e9, 101),
            },
            "freq_descriptions": {
                "0.800 GHz": "Lowest Fc?",
                "1.580 GHz": "N2 Lowest \n Freq Content", "3.625 GHz": "N48 Mid-Band",
                "4.250 GHz": "Highest Fc", "5.000 GHz": "Highest Freq Content",
                "6.796 GHz": "Lowest Alias Freq", "7.816 GHz": "N48 Alias Freq",
                "Cutoff_-3dB_GHz": "3dB Cutoff Freq", "Freq_at_15dB_GHz": "15dB Gain BW Start",
                "OP1dB": "Output P1dB"
            },
            # --- NEW: Add custom titles for this case ---
            "titles": {
                "table": "Amplifier Options Summary",
                "mag_plot": "S21 Gain vs. Frequency",
                "phase_plot": "Amplifier Phase Response",
                "gd_plot": "Amplifier Group Delay"
            }
        },
        "Diff_Amp_Analysis": {
            "description": "Analysis of Differential Amps",
            "s2p_directory": "C:\\Users\\adelgado.LT-PF3YBWF8\\Documents\\Design Files\\Phase Path board\\S2P Files\\PushPullAmps",
            "absolute_threshold_db": 15,
            "absolute_threshold_direction": 'rising',
            "custom_data": None,
            "frequency_sweeps": {
                'table': np.array([800e6, 1.580e9, 3.625e9, 4.25e9, 5e9, 6.796e9, 7.816e9]),
                'mag':   np.linspace(1e9, 9e9, 201),
                'phase': np.linspace(1e9, 6e9, 201),
                'gd':    np.linspace(1e9, 6e9, 101),
            },
            "freq_descriptions": {
                "0.800 GHz": "Lowest Fc?",
                "1.580 GHz": "N2 Lowest \n Freq Content", "3.625 GHz": "N48 Mid-Band",
                "4.250 GHz": "Highest Fc", "5.000 GHz": "Highest Freq Content",
                "6.796 GHz": "Lowest Alias Freq", "7.816 GHz": "N48 Alias Freq",
                "Cutoff_-3dB_GHz": "3dB Cutoff Freq", "Freq_at_15dB_GHz": "15dB Gain BW Start",
                "OP1dB": "Output P1dB"
            },
            # --- NEW: Add custom titles for this case ---
            "titles": {
                "table": "Amplifier Options Summary",
                "mag_plot": "S21 Gain vs. Frequency",
                "phase_plot": "Amplifier Phase Response",
                "gd_plot": "Amplifier Group Delay"
            }
        },
        "LPF_Analysis": {
            "description": "Analysis of LPF",
            "s2p_directory": "C:\\Users\\adelgado.LT-PF3YBWF8\\Documents\\Design Files\\Phase Path board\\S2P Files\\LPFs",
            "absolute_threshold_db": None,
            "absolute_threshold_direction": 'rising',
            "custom_data": None,
            "frequency_sweeps": {
                'table': np.array([50e6, 3.980e9, 5e9, 6.796e9, 7.816e9]),
                'mag':   np.linspace(1e9, 9e9, 201),
                'phase': np.linspace(1e9, 6e9, 201),
                'gd':    np.linspace(1e9, 6e9, 101),
            },
            "freq_descriptions": {
                "0.050 GHz": "Lowest Freq Content?",
                "3.980 GHz": "N48 Highest \n Freq Content",
                "5.000 GHz": "Highest Freq Content",
                "6.796 GHz": "Lowest Alias Freq", "7.816 GHz": "N48 Alias Freq",
                "Cutoff_-3dB_GHz": "3dB Cutoff Freq", "Freq_at_15dB_GHz": "15dB Gain BW Start",
                "OP1dB": "Output P1dB"
            },
            # --- NEW: Add custom titles for this case ---
            "titles": {
                "table": "LPF Options Summary",
                "mag_plot": "S21 Gain vs. Frequency",
                "phase_plot": "Amplifier Phase Response",
                "gd_plot": "Amplifier Group Delay"
            }
        },
        "CBRS_BPF_Analysis": {
            "description": "Analysis of BPF",
            "s2p_directory": "C:\\Users\\adelgado.LT-PF3YBWF8\\Documents\\Design Files\\Phase Path board\\S2P Files\\CBRS_BPFs",
            "absolute_threshold_db": None,
            "absolute_threshold_direction": 'rising',
            "custom_data": None,
            "frequency_sweeps": {
                'table': np.array([2.850e9, 2.95e9, 3.225e9, 3.980e9, 4.4e9, 7.396e9, 7.816e9]),
                'mag':   np.linspace(1e9, 9e9, 201),
                'phase': np.linspace(1e9, 6e9, 201),
                'gd':    np.linspace(1e9, 6e9, 101),
            },
            "freq_descriptions": {
                "2.850 GHz": "Lowest Freq Content\n3600 - 750MHz",
                "2.950 GHz": "Lowest Caladan Spur",
                "3.225 GHz": "Lowest Freq Content\n3600 - 375MHz",
                "3.980 GHz": "N48 Highest 40MHz\n Freq Content",
                "4.400 GHz": "N48 Highest Freq Content\n3650 + 750MHz",
                "7.396 GHz": "100MHz Lowest\n Alias Freq",
                "7.816 GHz": "40MHz Alias Freq",
                "Passband_Start_-3dB_GHz": "Passband Start (-3dB)",   # NEW
                "Cutoff_-3dB_GHz": "Passband End (-3dB)",
                "OP1dB": "Output P1dB"
            },
            "titles": {
                "table": "BPF S21 Summary",
                "mag_plot": "S21 Gain vs. Frequency",
                "phase_plot": "BPF Phase Response",
                "gd_plot": "BPF Group Delay"
            },
            "color_ranges": {
            "2.850 GHz": {"vmin": -30, "vmax": -13},
            "2.950 GHz": {"vmin": -30, "vmax": -13},
            "3.225 GHz": {"vmin": -3, "vmax": 0},
            "3.980 GHz": {"vmin": -3, "vmax": 0},
            "4.400 GHz": {"vmin": -3, "vmax": 0},
            "7.396 GHz": {"vmin": -100, "vmax": -30},
            "7.816 GHz": {"vmin": -100, "vmax": -30}
            },
            "strict_range": True
        }
    }

    cases_to_run = ["Diff_Amp_Analysis"] 

    for case_name in cases_to_run:
        if case_name not in analysis_cases:
            print(f"Warning: Case '{case_name}' not found. Skipping.")
            continue
            
        params = analysis_cases[case_name]
        output_filename_base = case_name 
        
        print(f"\n{'='*25}\nRUNNING ANALYSIS: {case_name}\nDescription: {params['description']}\n{'='*25}\n")
        
        all_data = process_s2p_data(
            params['s2p_directory'],
            freq_sweeps=params['frequency_sweeps'],
            absolute_threshold_db=params.get('absolute_threshold_db'),
            absolute_threshold_direction=params.get('absolute_threshold_direction', 'falling'),
            custom_data_df=params.get('custom_data')
        )

        df_table = all_data['table']
        print("\nGenerated Data Table:"); print(df_table.round(2))
        
        titles = params.get("titles", {})
        
        create_matplotlib_table(df_table, 
                                filename=f"{output_filename_base}_table.png", 
                                title=titles.get("table", "S21 Performance Summary"),
                                freq_descriptions=params.get('freq_descriptions'),
                                color_ranges=params.get('color_ranges'),
                                strict_range=params.get('strict_range'))
        
        plot_s21_curves(all_data['mag'], 
                        filename=f"{output_filename_base}_mag_plot.png",
                        title=titles.get("mag_plot", "S21 Transmission vs. Frequency"))
                        
        plot_s21_phase_curves(all_data['phase'], 
                              filename=f"{output_filename_base}_phase_plot.png",
                              title=titles.get("phase_plot", "S21 Phase vs. Frequency"))
                              
        plot_group_delay_curves(all_data['gd'], 
                                filename=f"{output_filename_base}_gd_plot.png",
                                title=titles.get("gd_plot", "Group Delay vs. Frequency"))
        
        print(f"\n--- Completed: {case_name} ---")

if __name__ == "__main__":
    main()
