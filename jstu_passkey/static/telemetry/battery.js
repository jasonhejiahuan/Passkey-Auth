function durationBucket(value) {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.min(Math.round(value / 900) * 900, 86_400);
}

export async function readBattery() {
  const battery = await navigator.getBattery();
  return {
    supported: true,
    charging: Boolean(battery.charging),
    levelBucket: Math.round(Number(battery.level || 0) * 10) / 10,
    chargingTimeBucket: durationBucket(battery.chargingTime),
    dischargingTimeBucket: durationBucket(battery.dischargingTime),
  };
}
