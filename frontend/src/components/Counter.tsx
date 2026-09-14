import { useEffect, useRef, useState } from 'react';
import { animate } from 'animejs';

export default function Counter({
  value,
  className,
  animateChanges = true,
}: {
  value: number;
  className?: string;
  animateChanges?: boolean;
}) {
  const [display, setDisplay] = useState(value);
  const displayRef = useRef(value);
  const prevValueRef = useRef(value);
  const [reduceMotion, setReduceMotion] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setReduceMotion(media.matches);
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    const valueChanged = !Object.is(value, prevValueRef.current);

    if (!animateChanges || reduceMotion) {
      prevValueRef.current = value;
      displayRef.current = value;
      setDisplay(value);
      return;
    }

    if (!valueChanged) return;

    const obj = { v: displayRef.current };
    prevValueRef.current = value;
    const anim = animate(obj, {
      v: value,
      duration: 900,
      ease: 'outExpo',
      onUpdate: () => {
        const next = Math.round(obj.v);
        displayRef.current = next;
        setDisplay(next);
      },
      onComplete: () => {
        displayRef.current = value;
        setDisplay(value);
      },
    });
    return () => anim?.pause?.();
  }, [animateChanges, reduceMotion, value]);

  return <span className={className}>{display}</span>;
}
