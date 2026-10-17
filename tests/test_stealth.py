import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hashflow.stealth import StealthLimiter, ThermalGuard

def test_stealth_limiter_no_limit():
    limiter = StealthLimiter(cpu_limit=0, stealth_mode=False)
    assert limiter.cpu_limit == 0
    assert limiter.calculate_adaptive_delay(50, 4) == 0

def test_stealth_limiter_with_limit():
    limiter = StealthLimiter(cpu_limit=30, stealth_mode=False)
    delay_under = limiter.calculate_adaptive_delay(20, 4)
    assert delay_under == 0 or delay_under < 0.5

    delay_over = limiter.calculate_adaptive_delay(80, 4)
    assert delay_over > 0

def test_refresh_randomization():
    limiter = StealthLimiter(cpu_limit=30, stealth_mode=True)
    intervals = [limiter.get_refresh_interval(3.0) for _ in range(10)]
    # Should have variance
    assert len(set([round(i,1) for i in intervals])) > 1

def test_thermal_guard():
    guard = ThermalGuard()
    # Should not crash even if no sensors
    temp = guard.get_temps()
    # temp can be None, that's ok
    overheating, t = guard.is_overheating()
    assert isinstance(overheating, bool)

if __name__ == "__main__":
    test_stealth_limiter_no_limit()
    test_stealth_limiter_with_limit()
    test_refresh_randomization()
    test_thermal_guard()
    print("All stealth tests passed")
