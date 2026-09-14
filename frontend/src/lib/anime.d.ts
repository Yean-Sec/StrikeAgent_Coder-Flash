declare module 'animejs' {
  export function animate(targets: any, params: any): any;
  export function createTimeline(params?: any): any;
  export function createTimer(params?: any): any;
  export function stagger(value: any, params?: any): any;
  export const utils: any;
  export const svg: any;
}

declare module 'animejs/svg' {
  export function createDrawable(selector: any, start?: number, end?: number): any;
  export function createMotionPath(path: any): any;
  export function morphTo(path: any, precision?: number): any;
}
