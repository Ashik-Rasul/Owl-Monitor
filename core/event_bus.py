from typing import Callable, Dict, List
from collections import defaultdict
from core.logger import setup_logger

logger = setup_logger(__name__)

class EventBus:
    """
    A publish-subscribe Event Bus. 
    Allows Collectors to publish events and Detection Engines to subscribe to them.
    """
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)

    def subscribe(self, event_type: str, callback: Callable):
        self.subscribers[event_type].append(callback)
        owner = getattr(callback, '__self__', None)
        class_prefix = f"{owner.__class__.__name__}." if owner else ""
        func_name = getattr(callback, '__name__', str(callback))
        logger.info(f"Subscribed {class_prefix}{func_name} to event: {event_type}")

    def publish(self, event_type: str, data: dict):
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Error in subscriber {callback.__name__}: {e}")
