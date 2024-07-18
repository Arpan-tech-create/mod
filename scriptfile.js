
<script>
    var chartData={{ chart_data| safe}};
    var chart;
    var selectedSlice=null;
    
    Highcharts.chart('chartContainer',
    
    {
    chart:
    {
        plotBackgroundColor:null,
        plotBorderWidth:null,
        plotShadow:false,
        type:'pie',
        events:{
            load:function()
            {
                chart = this;
            }
        }
    },
    title:
    {
        text:'Browser Market Share'
    },
    tooltip:
    {
        pointFormat:'{point.y:.2f}%'},
        
        plotOptions:
        {
            pie:
            {
                allowPointSelect:true,
                showInLegend:true,
                cursor:'pointer',
                dataLabels:
                {
                    enabled:true,
                    format:'{point.percentage:.2f}%',
                    distance:-50,
                    style:
                    {
                        fontWeight:'bold',
                        color:'white'
                    }
                },
                point:
                {
                    events:
                    {
                        click:function()
                        {
                            if(selectedSlice===this)
                            {
                                resetChart();
                            }
                            else{
                                selectedSlice = this;updateChart();
                            }
                        }
                    }
                }
            },
            series:
            {
                events:
                {
                    legendItemClick:function()
                    {
                        return false;
                    }
                }
            }
        },
        series:
        [{
            name:'Browsers',
            data:chartData
        }],
        legend:
        {
            enabled:true
        }
        }
        );
        function updateChart()
        {
        chart.series[0].points.forEach(function (point)
         { 
            if (point === selectedSlice) 
            {
                 point.graphic.element.classList.remove('blur-slice'); 
                 point.dataLabel.element.classList.remove('blur-slice'); 
                } 
                else 
                { 
                    point.graphic.element.classList.add('blur-slice'); 
                    point.dataLabel.element.classList.add('blur-slice'); 
                } 
            }
            );
            var title="Browser Market Share";
            if(selectedSlice)
            {
                title = "Pie by " + selectedSlice.name;
            }
    chart.setTitle({text:title});}
    function resetChart()
    {
    chart.series[0].points.forEach(function (point) 
    { 
        point.graphic.element.classList.remove('blur-slice'); 
        point.dataLabel.element.classList.remove('blur-slice'); 
        }
        );
        selectedSlice=null;chart.setTitle({text:'Browser Market Share'});
        }
    </script>