"""
Performance instrumentation for crypto operations.
Tracks timing, throughput, and resource usage of cryptographic operations.
"""

import time
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict
import statistics


@dataclass
class CryptoMetric:
    """Single crypto operation metric."""
    operation: str
    duration: float  # in seconds
    timestamp: float
    success: bool
    bytes_processed: int = 0
    additional_info: Dict[str, Any] = field(default_factory=dict)


class CryptoInstrumentation:
    """
    Instrumentation system for tracking crypto operation performance.
    Thread-safe metric collection.
    """
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.metrics: List[CryptoMetric] = []
        self.lock = threading.Lock()
        self.active_operations: Dict[str, float] = {}  # operation -> start_time
        
        # Aggregated statistics
        self.stats: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'total_time': 0.0,
            'min_time': float('inf'),
            'max_time': 0.0,
            'success_count': 0,
            'failure_count': 0,
            'total_bytes': 0
        })
    
    def start_operation(self, operation: str) -> None:
        """Start tracking an operation."""
        with self.lock:
            self.active_operations[operation] = time.time()
    
    def end_operation(
        self,
        operation: str,
        success: bool = True,
        bytes_processed: int = 0,
        **kwargs
    ) -> Optional[float]:
        """
        End tracking an operation and record metric.
        
        Returns:
            Duration in seconds, or None if operation wasn't tracked
        """
        with self.lock:
            if operation not in self.active_operations:
                return None
            
            start_time = self.active_operations.pop(operation)
            duration = time.time() - start_time
            
            metric = CryptoMetric(
                operation=operation,
                duration=duration,
                timestamp=time.time(),
                success=success,
                bytes_processed=bytes_processed,
                additional_info=kwargs
            )
            
            self.metrics.append(metric)
            
            # Update statistics
            stats = self.stats[operation]
            stats['count'] += 1
            stats['total_time'] += duration
            stats['min_time'] = min(stats['min_time'], duration)
            stats['max_time'] = max(stats['max_time'], duration)
            
            if success:
                stats['success_count'] += 1
            else:
                stats['failure_count'] += 1
            
            stats['total_bytes'] += bytes_processed
            
            # Trim history if needed
            if len(self.metrics) > self.max_history:
                self.metrics = self.metrics[-self.max_history:]
            
            return duration
    
    def get_stats(self, operation: Optional[str] = None) -> Dict:
        """
        Get statistics for an operation or all operations.
        
        Args:
            operation: Specific operation name, or None for all operations
            
        Returns:
            Dictionary of statistics
        """
        with self.lock:
            if operation:
                if operation not in self.stats:
                    return {}
                stats = self.stats[operation].copy()
                if stats['count'] > 0:
                    stats['avg_time'] = stats['total_time'] / stats['count']
                    stats['throughput'] = stats['total_bytes'] / stats['total_time'] if stats['total_time'] > 0 else 0
                return stats
            else:
                # Return all stats
                result = {}
                for op, stats in self.stats.items():
                    result[op] = stats.copy()
                    if stats['count'] > 0:
                        result[op]['avg_time'] = stats['total_time'] / stats['count']
                        result[op]['throughput'] = stats['total_bytes'] / stats['total_time'] if stats['total_time'] > 0 else 0
                return result
    
    def get_recent_metrics(self, operation: Optional[str] = None, limit: int = 100) -> List[CryptoMetric]:
        """
        Get recent metrics for an operation or all operations.
        
        Args:
            operation: Specific operation name, or None for all operations
            limit: Maximum number of metrics to return
            
        Returns:
            List of recent metrics
        """
        with self.lock:
            if operation:
                filtered = [m for m in self.metrics if m.operation == operation]
                return filtered[-limit:]
            else:
                return self.metrics[-limit:]
    
    def get_operation_times(self, operation: str) -> List[float]:
        """Get all durations for a specific operation."""
        with self.lock:
            return [m.duration for m in self.metrics if m.operation == operation]
    
    def get_percentiles(self, operation: str, percentiles: List[float] = [50, 90, 95, 99]) -> Dict[float, float]:
        """
        Get percentile latencies for an operation.
        
        Args:
            operation: Operation name
            percentiles: List of percentiles to calculate (0-100)
            
        Returns:
            Dictionary mapping percentile to latency
        """
        times = self.get_operation_times(operation)
        if not times:
            return {}
        
        times.sort()
        result = {}
        for p in percentiles:
            idx = int(len(times) * p / 100)
            result[p] = times[min(idx, len(times) - 1)]
        
        return result
    
    def reset(self) -> None:
        """Reset all metrics and statistics."""
        with self.lock:
            self.metrics.clear()
            self.stats.clear()
            self.active_operations.clear()


# Global instrumentation instance
_instrumentation = CryptoInstrumentation()


def get_instrumentation() -> CryptoInstrumentation:
    """Get the global instrumentation instance."""
    return _instrumentation


def instrumented(operation_name: str):
    """
    Decorator to instrument a function with timing.
    
    Usage:
        @instrumented("kem_key_generation")
        def generate_keys():
            ...
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            inst = get_instrumentation()
            inst.start_operation(operation_name)
            try:
                result = func(*args, **kwargs)
                # Try to get bytes_processed from result if possible
                bytes_processed = 0
                if isinstance(result, tuple):
                    # If function returns tuple, sum up bytes from tuple elements
                    for item in result:
                        if isinstance(item, bytes):
                            bytes_processed += len(item)
                elif isinstance(result, bytes):
                    bytes_processed = len(result)
                
                inst.end_operation(operation_name, success=True, bytes_processed=bytes_processed)
                return result
            except Exception as e:
                inst.end_operation(operation_name, success=False, error=str(e))
                raise
        return wrapper
    return decorator

