import { useRef, type KeyboardEvent } from "react";

export function Splitter({
  axis,
  value,
  min,
  max,
  label,
  onChange,
}: {
  axis: "horizontal" | "vertical";
  value: number;
  min: number;
  max: number;
  label: string;
  onChange: (value: number) => void;
}) {
  const origin = useRef<{ position: number; value: number } | null>(null);
  const clamp = (next: number) =>
    Math.round(Math.max(min, Math.min(max, next)));
  function keyDown(event: KeyboardEvent) {
    const increase = axis === "vertical" ? "ArrowRight" : "ArrowUp";
    const decrease = axis === "vertical" ? "ArrowLeft" : "ArrowDown";
    if (![increase, decrease, "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    onChange(
      clamp(
        event.key === "Home"
          ? min
          : event.key === "End"
            ? max
            : value + (event.key === increase ? 20 : -20),
      ),
    );
  }
  return (
    <div
      className={`workbench-splitter ${axis}`}
      role="separator"
      tabIndex={0}
      aria-label={label}
      aria-orientation={axis}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      onKeyDown={keyDown}
      onPointerDown={(event) => {
        origin.current = {
          position: axis === "vertical" ? event.clientX : event.clientY,
          value,
        };
        event.currentTarget.setPointerCapture(event.pointerId);
      }}
      onPointerMove={(event) => {
        if (!origin.current) return;
        const delta =
          axis === "vertical"
            ? event.clientX - origin.current.position
            : origin.current.position - event.clientY;
        onChange(clamp(origin.current.value + delta));
      }}
      onPointerUp={() => {
        origin.current = null;
      }}
      onPointerCancel={() => {
        origin.current = null;
      }}
      onLostPointerCapture={() => {
        origin.current = null;
      }}
    />
  );
}
