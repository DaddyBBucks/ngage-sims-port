"""Translate host frontend key transitions into the proven TWsEvent queue."""
from .input import KEYNAME_TO_SCANCODE


class HostInputBridge:
    """Stateful edge bridge; suppresses host repeat and orphan releases."""

    def __init__(self):
        self.pressed = set()
        self.key_down_events = 0
        self.key_up_events = 0
        self.ignored_events = 0

    def pump(self, frontend, event_queue):
        for action, key_name in frontend.poll_input():
            scancode = KEYNAME_TO_SCANCODE.get(key_name)
            if scancode is None:
                self.ignored_events += 1
                continue
            if action == "down":
                if key_name in self.pressed:
                    self.ignored_events += 1
                    continue
                self.pressed.add(key_name)
                event_queue.push_host_keydown(scancode)
                self.key_down_events += 1
            elif action == "up":
                if key_name not in self.pressed:
                    self.ignored_events += 1
                    continue
                self.pressed.remove(key_name)
                event_queue.push_host_keyup(scancode)
                self.key_up_events += 1
            else:
                self.ignored_events += 1

    def release_all(self, event_queue):
        for key_name in sorted(self.pressed):
            event_queue.push_host_keyup(KEYNAME_TO_SCANCODE[key_name])
            self.key_up_events += 1
        self.pressed.clear()

    def summary(self):
        return {
            "key_down_events": self.key_down_events,
            "key_up_events": self.key_up_events,
            "ignored_events": self.ignored_events,
            "pressed_at_end": sorted(self.pressed),
        }
