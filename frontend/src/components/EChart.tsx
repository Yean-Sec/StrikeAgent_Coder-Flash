import { memo, type ComponentProps } from 'react';
import ReactEChartsCore from 'echarts-for-react/lib/core';
import * as echarts from 'echarts/core';
import { BarChart, LineChart, PieChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
  BarChart,
  LineChart,
  PieChart,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  CanvasRenderer,
]);

type Props = Omit<ComponentProps<typeof ReactEChartsCore>, 'echarts'>;

/** 仅注册项目实际使用的 ECharts 模块，避免首页加载完整图表库。 */
const EChart = memo(function EChart(props: Props) {
  return <ReactEChartsCore echarts={echarts} {...props} />;
});

export default EChart;
