import fnmatch
import logging
import os
import re
import shutil
import time
from datetime import datetime
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILENAME = "rules.watch"
LOG_FILENAME = "sorter.log"
TEMP_EXTENSIONS = (".crdownload", ".part", ".tmp", ".opdownload", ".download")

logging.basicConfig(
    filename=os.path.join(SCRIPT_DIR, LOG_FILENAME),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def parse_size_to_bytes(value_str):
    """Converts plain-English sizes like '50 mb' or '1.5 gb' into bytes."""
    match = re.match(r"^\s*([\d.]+)\s*(b|kb|mb|gb)?\s*$", value_str.lower())
    if not match:
        raise ValueError(f"Invalid size format: '{value_str}'")
    num = float(match.group(1))
    unit = match.group(2) or "b"
    multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3}
    return num * multipliers[unit]


def parse_age_to_seconds(value_str):
    """Converts plain-English durations like '7 days' or '12 hours' into seconds."""
    match = re.match(r"^\s*([\d.]+)\s*(minute|minutes|hour|hours|day|days)?\s*$", value_str.lower())
    if not match:
        raise ValueError(f"Invalid time format: '{value_str}'")
    num = float(match.group(1))
    unit = match.group(2) or "days"
    if unit.startswith("minute"):
        return num * 60
    if unit.startswith("hour"):
        return num * 3600
    return num * 86400


def evaluate_clause(clause, ctx):
    """Evaluates a single plain-English condition clause against file metadata."""
    clause = clause.strip()
    if not clause or clause.lower() in ("always", "any file", "true"):
        return True

    # Negation wrapper: "not <clause>"
    if clause.lower().startswith("not "):
        return not evaluate_clause(clause[4:], ctx)

    # Size checks: "size is over 50 mb", "size is under 10 kb"
    size_match = re.match(r"^size\s+(?:is\s+)?(over|above|greater than|under|below|less than)\s+(.+)$", clause, re.I)
    if size_match:
        op, val = size_match.group(1).lower(), size_match.group(2)
        target_bytes = parse_size_to_bytes(val)
        if op in ("over", "above", "greater than"):
            return ctx["size"] > target_bytes
        return ctx["size"] < target_bytes

    # Age checks: "age is older than 7 days", "age is newer than 2 hours"
    age_match = re.match(r"^age\s+(?:is\s+)?(older than|over|newer than|under)\s+(.+)$", clause, re.I)
    if age_match:
        op, val = age_match.group(1).lower(), age_match.group(2)
        target_secs = parse_age_to_seconds(val)
        if op in ("older than", "over"):
            return ctx["age"] > target_secs
        return ctx["age"] < target_secs

    # Text & property checks: "<field> <operator> <values>"
    prop_match = re.match(
        r"^(extension|ext|name|filename|folder|host)\s+(is not|isn't|is|does not contain|doesn't contain|contains|starts with|ends with|matches wildcard|matches regex)\s+(.+)$",
        clause,
        re.I,
    )
    if not prop_match:
        raise ValueError(f"Could not understand condition: '{clause}'")

    field = prop_match.group(1).lower()
    op = prop_match.group(2).lower()
    raw_val = prop_match.group(3).strip()

    field_map = {
        "extension": ctx["ext"],
        "ext": ctx["ext"],
        "name": ctx["name"],
        "filename": ctx["filename"],
        "folder": ctx["host"],
        "host": ctx["host"],
    }
    actual = field_map[field]
    actual_lower = actual.lower()

    # Split comma-separated options (unless regex)
    if op == "matches regex":
        items = [raw_val.strip("'\"")]
    else:
        items = [i.strip().strip("'\"") for i in raw_val.split(",") if i.strip()]

    if field in ("extension", "ext"):
        items = [i.lower().lstrip(".") for i in items]

    if op == "is":
        return any(actual_lower == i.lower() for i in items)
    if op in ("is not", "isn't"):
        return all(actual_lower != i.lower() for i in items)
    if op == "contains":
        return any(i.lower() in actual_lower for i in items)
    if op in ("does not contain", "doesn't contain"):
        return all(i.lower() not in actual_lower for i in items)
    if op == "starts with":
        return any(actual_lower.startswith(i.lower()) for i in items)
    if op == "ends with":
        return any(actual_lower.endswith(i.lower()) for i in items)
    if op == "matches wildcard":
        return any(fnmatch.fnmatch(actual_lower, i.lower()) for i in items)
    if op == "matches regex":
        return bool(re.search(items[0], actual, re.I))

    return False


def evaluate_when(when_expression, ctx):
    """Evaluates compound plain-English conditions joined by 'OR' and 'AND'."""
    or_groups = re.split(r"\s+OR\s+", when_expression, flags=re.I)
    for group in or_groups:
        and_clauses = re.split(r"\s+AND\s+", group, flags=re.I)
        if all(evaluate_clause(c, ctx) for c in and_clauses):
            return True
    return False


def parse_plain_english_config():
    """Parses the plain-English config.txt file into structured rules."""
    config_path = os.path.join(SCRIPT_DIR, CONFIG_FILENAME)

    if not os.path.exists(config_path):
        write_default_english_config(config_path)
        return None

    with open(config_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    variables = {}
    power = "OFF"
    watch_dirs = []
    rules = []
    current_rule = None

    def apply_vars(text):
        for k, v in sorted(variables.items(), key=lambda x: -len(x[0])):
            text = text.replace(f"${k}", v)
        return text

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # Variable definitions: $DL = C:\Users\Max\Downloads
        if line.startswith("$") and "=" in line and not current_rule:
            var_name, var_val = line[1:].split("=", 1)
            variables[var_name.strip()] = apply_vars(var_val.strip().strip("'\""))
            continue

        upper_line = line.upper()

        # Global settings
        if upper_line.startswith("POWER"):
            _, val = line.split("=", 1)
            power = val.strip().strip("'\"").upper()
            continue

        if upper_line.startswith("WATCH"):
            _, val = line.split("=", 1)
            expanded = apply_vars(val.strip())
            for p in expanded.split(","):
                clean_p = p.strip().strip("'\"")
                if clean_p:
                    watch_dirs.append(os.path.abspath(clean_p))
            continue

        # Rule header: [Rule Name]
        if line.startswith("[") and line.endswith("]"):
            if current_rule:
                rules.append(current_rule)
            current_rule = {
                "name": line[1:-1].strip(),
                "when": [],
                "actions": [],
                "stop": True,
            }
            continue

        # Rule statements
        if current_rule:
            if upper_line.startswith("WHEN "):
                current_rule["when"].append(apply_vars(line[5:].strip()))
            elif upper_line.startswith("AND ") and not upper_line.startswith("AND KEEP GOING"):
                # Allows multi-line WHEN readability:
                # WHEN extension is mp4
                # AND name contains caseoh
                if current_rule["when"]:
                    current_rule["when"][-1] += " AND " + apply_vars(line[4:].strip())
            elif upper_line.startswith("THEN "):
                current_rule["actions"].append(apply_vars(line[5:].strip()))
            elif upper_line in ("AND KEEP GOING", "KEEP GOING", "CONTINUE"):
                current_rule["stop"] = False

    if current_rule:
        rules.append(current_rule)

    return {
        "power": power,
        "watch_dirs": watch_dirs,
        "rules": rules,
    }


def write_default_english_config(config_path):
    """Creates a clean, plain-English starter config.txt."""
    template = """# ==========================================
# LIVE FILE AUTOMATOR (PLAIN ENGLISH MODE)
# ==========================================
$DL = C:\\Users\\Max\\Downloads

POWER = ON
WATCH = $DL

[Caseoh Clip Media]
WHEN name contains Caseoh
THEN move to $DL\\Caseoh Clip Media

[General Media]
WHEN extension is mp4, mkv, mov, mp3
AND name does not start with temp_
THEN move to $DL\\General Media

[General Images]
WHEN extension is png, jpg, jpeg, gif
THEN move to $DL\\General Images

[Random Stuff]
WHEN extension is docx, pdf, mcpack, json, exe
THEN move to $DL\\Random Stuff
"""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(template)
    logging.info(f"Created plain-English starter config at: {config_path}")

def is_file_ready(file_path, wait_time=0.5):
    """Checks that a file has finished downloading and is not locked."""
    try:
        initial_size = os.path.getsize(file_path)
        time.sleep(wait_time)
        if not os.path.exists(file_path):
            return False
        current_size = os.path.getsize(file_path)
        if initial_size != current_size:
            return False
        with open(file_path, "ab"):
            pass
        return True
    except (OSError, IOError):
        return False


def resolve_unique_path(target_dir, filename):
    """Appends _1, _2, etc. if the destination file already exists."""
    os.makedirs(target_dir, exist_ok=True)
    dest_path = os.path.join(target_dir, filename)
    if os.path.exists(dest_path):
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(target_dir, f"{base}_{counter}{ext}")
            counter += 1
    return dest_path


def format_tokens(text, file_path):
    """Replaces {name}, {ext}, {year}, {month}, {day}, and {folder} tokens."""
    now = datetime.now()
    filename = os.path.basename(file_path)
    base, ext = os.path.splitext(filename)
    parent_folder = os.path.basename(os.path.dirname(file_path))

    tokens = {
        "{filename}": filename,
        "{name}": base,
        "{ext}": ext.lstrip("."),
        "{year}": now.strftime("%Y"),
        "{month}": now.strftime("%m"),
        "{day}": now.strftime("%d"),
        "{folder}": parent_folder,
    }
    for token, val in tokens.items():
        text = text.replace(token, val)
    return text


def run_english_action(action_line, current_path, rule_name):
    """Executes a plain-English THEN command and returns the updated file path."""
    if not current_path or not os.path.exists(current_path):
        return None

    text = format_tokens(action_line.strip(), current_path)
    lower = text.lower()
    filename = os.path.basename(current_path)

    # Action: "move to <folder>"
    if lower.startswith("move to "):
        target_dir = os.path.abspath(text[8:].strip().strip("'\""))
        if os.path.dirname(current_path) == target_dir:
            return current_path
        dest = resolve_unique_path(target_dir, filename)
        shutil.move(current_path, dest)
        logging.info(f"[{rule_name}] Moved '{filename}' -> '{dest}'")
        return dest

    # Action: "copy to <folder>"
    if lower.startswith("copy to "):
        target_dir = os.path.abspath(text[8:].strip().strip("'\""))
        dest = resolve_unique_path(target_dir, filename)
        shutil.copy2(current_path, dest)
        logging.info(f"[{rule_name}] Copied '{filename}' -> '{dest}'")
        return current_path

    # Action: "rename to <new_filename>"
    if lower.startswith("rename to "):
        new_name = text[10:].strip().strip("'\"")
        parent_dir = os.path.dirname(current_path)
        dest = resolve_unique_path(parent_dir, new_name)
        os.rename(current_path, dest)
        logging.info(f"[{rule_name}] Renamed '{filename}' -> '{os.path.basename(dest)}'")
        return dest

    # Action: "delete" or "delete file"
    if lower in ("delete", "delete file"):
        os.remove(current_path)
        logging.info(f"[{rule_name}] Deleted '{filename}'")
        return None

    # Action: "log <message>"
    if lower.startswith("log "):
        msg = text[4:].strip().strip("'\"")
        logging.info(f"[{rule_name}] {msg}")
        return current_path

    logging.error(f"[{rule_name}] Unknown action: '{action_line}'")
    return current_path

class PlainEnglishSorterHandler(FileSystemEventHandler):
    """Evaluates files using the plain-English rules from config.txt."""

    def __init__(self, host_dir, rules):
        self.host_dir = os.path.abspath(host_dir)
        self.rules = rules
        self.in_progress = set()

    def get_file_context(self, file_path):
        stat = os.stat(file_path)
        filename = os.path.basename(file_path)
        base, ext = os.path.splitext(filename)
        return {
            "filename": filename,
            "name": base,
            "ext": ext.lstrip(".").lower(),
            "size": stat.st_size,
            "age": time.time() - stat.st_mtime,
            "host": os.path.basename(self.host_dir),
        }

    def process_file(self, source_file_path):
        source_file_path = os.path.abspath(source_file_path)

        if source_file_path in self.in_progress or not os.path.isfile(source_file_path):
            return

        filename = os.path.basename(source_file_path)
        lower_name = filename.lower()

        if (
            filename in (CONFIG_FILENAME, LOG_FILENAME)
            or lower_name.endswith(".bat")
            or lower_name.endswith(".pyw")
            or lower_name.endswith(TEMP_EXTENSIONS)
        ):
            return

        self.in_progress.add(source_file_path)
        try:
            if not is_file_ready(source_file_path):
                return

            current_path = source_file_path
            for rule in self.rules:
                if not current_path or not os.path.exists(current_path):
                    break

                ctx = self.get_file_context(current_path)
                when_expr = " AND ".join(rule["when"]) if rule["when"] else "always"

                try:
                    matched = evaluate_when(when_expr, ctx)
                except Exception as e:
                    logging.error(f"[{rule['name']}] Rule error: {e}")
                    continue

                if matched:
                    for action in rule["actions"]:
                        current_path = run_english_action(action, current_path, rule["name"])
                        if not current_path:
                            break
                    if rule["stop"]:
                        break
        except Exception as e:
            logging.error(f"Error processing '{filename}': {e}")
        finally:
            self.in_progress.discard(source_file_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_file(event.dest_path)


class ConfigWatchHandler(FileSystemEventHandler):
    """Hot-reloads config.txt automatically whenever you save changes."""

    def __init__(self, controller):
        self.controller = controller
        self.config_path = os.path.abspath(os.path.join(SCRIPT_DIR, CONFIG_FILENAME))
        self.last_reload = 0

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.config_path:
            now = time.time()
            if now - self.last_reload < 1.0:
                return
            self.last_reload = now
            time.sleep(0.1)
            self.controller.check_and_update_state()


class SorterController:
    """Manages active folder watchers."""

    def __init__(self):
        self.observers = []
        self.is_active = False

    def check_and_update_state(self):
        config = parse_plain_english_config()
        if not config:
            self.stop_sorting()
            return

        if config["power"] != "ON" or not config["watch_dirs"] or not config["rules"]:
            if self.is_active:
                logging.info("POWER OFF or missing WATCH/rules. Pausing...")
                self.stop_sorting()
            return

        if self.is_active:
            self.stop_sorting()

        valid_count = 0
        for watch_dir in config["watch_dirs"]:
            if not os.path.exists(watch_dir):
                logging.error(f"WATCH path does not exist: {watch_dir}")
                continue

            logging.info(f"Watching '{watch_dir}' with {len(config['rules'])} rule(s).")
            handler = PlainEnglishSorterHandler(watch_dir, config["rules"])

            for fname in os.listdir(watch_dir):
                handler.process_file(os.path.join(watch_dir, fname))

            obs = Observer()
            obs.schedule(handler, path=watch_dir, recursive=False)
            obs.start()
            self.observers.append(obs)
            valid_count += 1

        self.is_active = valid_count > 0

    def stop_sorting(self):
        if self.is_active and self.observers:
            for obs in self.observers:
                obs.stop()
                obs.join()
            self.observers.clear()
            self.is_active = False
            logging.info("Sorter stopped.")


def main():
    logging.info("--- Starting Plain-English File Automator ---")
    controller = SorterController()
    controller.check_and_update_state()

    config_handler = ConfigWatchHandler(controller)
    config_observer = Observer()
    config_observer.schedule(config_handler, path=SCRIPT_DIR, recursive=False)
    config_observer.start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        controller.stop_sorting()
        config_observer.stop()

    config_observer.join()


if __name__ == "__main__":
    main()