# MIT License – Copyright (c) 2025 Menny Levinski

"""
This is only a demo program, not a real app.

It demonstrates a full audit workflow with console progress animation and logging.
"""

import io
import sys
import threading
import tkinter as tk
from datetime import datetime
import time
import traceback

# --- Logger system ---
class ConsoleLogger:
    """Redirects stdout and stderr to console widget and internal log buffer."""
    def __init__(self, console_widget: tk.Text):
        self.console = console_widget
        self._wrap_enabled = True
        self._log_buffer = io.StringIO()

        # Save original streams
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

        class TeeStream:
            def __init__(self, *streams):
                self.streams = streams
            def write(self, data):
                for s in self.streams:
                    try:
                        s.write(data)
                        s.flush()
                    except Exception:
                        pass
            def flush(self):
                for s in self.streams:
                    try:
                        s.flush()
                    except Exception:
                        pass

        sys.stdout = TeeStream(self._orig_stdout, self._log_buffer)
        sys.stderr = TeeStream(self._orig_stderr, self._log_buffer)

        sys.excepthook = self._log_exceptions
        self.log(f"Logger initialized: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _ts(self):
        return datetime.now().strftime("[%H:%M:%S]")

    def _log_exceptions(self, exc_type, exc_value, exc_traceback):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=self._log_buffer)

    def log(self, message: str):
        """Log message to console widget and buffer"""
        ts_message = f"{self._ts()} {message}"

        self._log_buffer.write(ts_message + "\n")
        self._log_buffer.flush()

        if self._wrap_enabled:
            self.console.config(state="normal")
            self.console.insert(tk.END, ts_message + "\n")
            self.console.see(tk.END)
            self.console.config(state="disabled")
            self.console.update()

    def save_to_file(self):
        filename = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(self._log_buffer.getvalue())
        self.log(f"[Log saved to {filename}]")

# --- Mock workflow functions ---
def mock_check(logger: ConsoleLogger, name: str):
    """Simulate a module check with animated dots, fully logged."""
    dots_running = [True]
    dot_count = [0]

    # Log the step name through the logger (adds to buffer)
    ts = datetime.now().strftime("[%H:%M:%S]")
    logger._log_buffer.write(f"{ts} -> {name} ")
    logger._log_buffer.flush()

    # Insert into console widget
    logger.console.config(state="normal")
    logger.console.insert(tk.END, f"{ts} -> {name} ")
    logger.console.see(tk.END)
    logger.console.config(state="disabled")

    def animate_dots():
        if not dots_running[0] or dot_count[0] >= 10:
            return
        logger.console.config(state="normal")
        logger.console.insert(tk.END, ".")
        logger.console.see(tk.END)
        logger.console.config(state="disabled")
        dot_count[0] += 1
        logger.console.after(200, animate_dots)

    animate_dots()

    # Simulate work
    for _ in range(3):
        time.sleep(0.3)

    # Stop dots and add checkmark
    dots_running[0] = False
    logger.console.config(state="normal")
    logger.console.insert(tk.END, " ✓\n")
    logger.console.see(tk.END)
    logger.console.config(state="disabled")

    # Also log to buffer for file saving
    logger._log_buffer.write(" ✓\n")
    logger._log_buffer.flush()

def mock_assemble_report(logger: ConsoleLogger):
    """Simulate assembling a report"""
    logger.log("\nAssembling final report...")
    time.sleep(1)

# --- GUI ---
class WorkflowGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Example - Workflow with Logger")
        self.geometry("600x400")

        # Console widget
        self.console = tk.Text(self, height=20, width=80)
        self.console.pack(pady=10)
        self.logger = ConsoleLogger(self.console)

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Run Full Audit", command=self.run_all_audit).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Save Log File ", command=self.logger.save_to_file).pack(side="left", padx=5)

    def run_all_audit(self):
        # --- Clear previous output ---
        self.console.config(state="normal")
        self.console.delete("1.0", tk.END)
        self.console.config(state="disabled")
        self.logger._log_buffer = io.StringIO()  # reset the log buffer

        self.logger.log("\nStarting workflow example...")

        # --- Disable buttons while audit runs ---
        for child in self.children.values():
            if isinstance(child, tk.Frame):
                for btn in child.winfo_children():
                    btn.config(state="disabled")

        steps = ["System Scan", "Network Scan", "Security Check", " Summarizing Review", "Finalize Audit"]

        def worker():
            for step in steps:
                mock_check(self.logger, step)
            mock_assemble_report(self.logger)
            self.logger.log("Workflow example finished.\n")

            # --- Re-enable buttons when done ---
            for child in self.children.values():
                if isinstance(child, tk.Frame):
                    for btn in child.winfo_children():
                        btn.config(state="normal")

        threading.Thread(target=worker, daemon=True).start()

# --- Run example ---
if __name__ == "__main__":
    app = WorkflowGUI()
    app.mainloop()
