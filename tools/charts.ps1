$prismRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$prismMedia = Join-Path $prismRoot 'media'
$prismReport = Get-Content -LiteralPath (Join-Path $prismRoot 'evidence\verification.json') -Raw | ConvertFrom-Json
if ($prismReport.gadget_model.unsafe_cross_sum_total_variation -ne 0.2) { throw 'Unexpected model result' }
Add-Type -AssemblyName System.Windows.Forms.DataVisualization

function New-PrismChart([string]$title) {
    $plot = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $plot.Width = 1120
    $plot.Height = 560
    $plot.BackColor = [Drawing.Color]::FromArgb(8,19,34)
    $area = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 'Data'
    $area.BackColor = [Drawing.Color]::FromArgb(16,34,55)
    $area.AxisX.LabelStyle.ForeColor = [Drawing.Color]::White
    $area.AxisY.LabelStyle.ForeColor = [Drawing.Color]::White
    $area.AxisX.LineColor = [Drawing.Color]::LightSlateGray
    $area.AxisY.LineColor = [Drawing.Color]::LightSlateGray
    $area.AxisX.MajorGrid.Enabled = $false
    $area.AxisY.MajorGrid.LineColor = [Drawing.Color]::FromArgb(45,70,96)
    $area.AxisX.TitleForeColor = [Drawing.Color]::White
    $area.AxisY.TitleForeColor = [Drawing.Color]::White
    $area.AxisX.Title = 'Observed field value (F5)'
    $area.AxisY.Title = 'Exact probability'
    $area.AxisY.Minimum = 0
    $area.AxisY.Maximum = 0.42
    $area.AxisY.Interval = 0.1
    [void]$plot.ChartAreas.Add($area)
    $legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend
    $legend.ForeColor = [Drawing.Color]::White
    $legend.BackColor = [Drawing.Color]::Transparent
    $legend.Docking = 'Bottom'
    [void]$plot.Legends.Add($legend)
    [void]$plot.Titles.Add($title)
    $plot.Titles[0].ForeColor = [Drawing.Color]::White
    $plot.Titles[0].Font = New-Object Drawing.Font('Segoe UI',18,[Drawing.FontStyle]::Bold)
    return $plot
}

$prismSafe = New-PrismChart 'Protected multiplier wire: identical distributions for both logical cases'
$prismUnsafe = New-PrismChart 'Unsafe cross-term sum: exact distinguishability = 0.20'
foreach ($plotAndMode in @(@($prismSafe,'safe'),@($prismUnsafe,'unsafe'))) {
    $plot = $plotAndMode[0]
    $mode = $plotAndMode[1]
    foreach ($case in 0,1) {
        $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series
        $series.Name = "logical product = $case"
        $series.ChartType = 'Column'
        $series.Color = if ($case -eq 0) { [Drawing.Color]::FromArgb(113,237,187) } else { [Drawing.Color]::FromArgb(237,196,123) }
        foreach ($value in 0..4) {
            $peak = if ($mode -eq 'safe') { 0 } else { $case }
            $probability = if ($value -eq $peak) { 0.36 } else { 0.16 }
            [void]$series.Points.AddXY([string]$value,$probability)
        }
        [void]$plot.Series.Add($series)
    }
    $plot.SaveImage((Join-Path $prismMedia ("model-" + $mode + '.png')),'Png')
    $plot.Dispose()
}
Write-Output 'Rendered exact-distribution charts from the verified F5 model.'
