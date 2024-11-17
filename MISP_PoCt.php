<?php
// Load and decode the JSON file into a PHP array
$jsonData = file_get_contents('https://www.circl.lu/doc/misp/feed-osint/manifest.json');
$manifestArray = json_decode($jsonData, true);
$manifest=array_keys($manifestArray);
shuffle($manifest);

function scanArray($array) {
    $totalAttributes = 0;
    $toIdsCount = 0;
    $deletedCount = 0;
    $threatLevelId = 0;
    $analysisLevel = 0;
    $eventTimestamp = 0;
    $eventDate = 0;
    $mitreReference = 0;
    $threatActor = 0;
    $tagCount =0;

    foreach ($array as $key => $value) {
        if ($key === "Event" && is_array($value)) {
            // Check if "threat_level_id" exists at the "Event" level
            if (isset($value["threat_level_id"])) $threatLevelId = $value["threat_level_id"];
            if (isset($value["timestamp"])) $eventTimestamp = $value["timestamp"];
            if (isset($value["date"])) $eventDate = $value["date"];
            if (isset($value["analysis"])) $analysisLevel = $value["analysis"];
        }

        if ($key === "Attribute" && is_array($value)) {
            // Count total elements within an "Attribute" array
            $totalAttributes += count($value);
            
            // Count "to_ids" and "deleted" keys within each "Attribute" element
            foreach ($value as $attribute) {
                if (is_array($attribute)) {
                    if (isset($attribute["to_ids"]) && $attribute["to_ids"] == 1) $toIdsCount++;
                    if (isset($attribute["deleted"]) && $attribute["deleted"] == 1) $deletedCount++;
                }
            }
        }

        // Check for "Tag" key and search for "mitre-attack-pattern" or "threat-actor"
        if ($key === "Tag" && is_array($value)) {
            $tagCount += count($value);
            foreach ($value as $tag) {
                if (is_array($tag) && isset($tag["name"])) {
                    $tagName = $tag["name"];
                    //echo "Checking tag: $tagName <br>"; // Debugging line to show tag names
                    if (strpos($tagName, "mitre") !== false) $mitreReference++;
                    if (strpos($tagName, "threat-actor") !== false) $threatActor++;
                }
            }
        }

        // Recursive call to handle sub-arrays
        else if (is_array($value)) {
            // Recursively process sub-arrays
            list($subTotalAttributes, $subToIdsCount, $subDeletedCount, $subTagCount, $subMitreReference, $subThreatActor) = scanArray($value);
            $totalAttributes += $subTotalAttributes;
            $toIdsCount += $subToIdsCount;
            $deletedCount += $subDeletedCount;
            $tagCount += $subTagCount;
            $mitreReference += $subMitreReference;
            $threatActor += $subThreatActor;
        }
    }

    // Return the results
    return [
        $totalAttributes, 
        $toIdsCount, 
        $deletedCount,
        $tagCount,  
        $mitreReference, 
        $threatActor,
        $threatLevelId, 
        $analysisLevel, 
        $eventTimestamp, 
        $eventDate
    ];
}





$i=0;
$limit=20;
$finalArray=array();
foreach($manifest as $key => $value) {
	$i++;
	if ($i>$limit) break;
	// Load and decode the JSON file into a PHP array
	$jsonData = file_get_contents("https://www.circl.lu/doc/misp/feed-osint/$value.json");
	$dataArray = json_decode($jsonData, true);

	// Get the total number of "Attribute" elements and "to_ids" fields with value 1
	list($totalAttributes, $toIdsCount, $deletedCount, $tagCount, $mitreReference, $threatActor, $threatLevelId, $analysisLevel, $eventTimestamp, $eventDate) = scanArray($dataArray);
	//echo "$value<br>";
	
	//TIMELINESS
	$now=time();
	$eventDate = strtotime($eventDate);
	$ETMI = 1-(($now-$eventTimestamp) / ($now-$eventDate));
	//echo "Normalized Event Timeliness Maintenance I: $ETMI<br>";
	$timeliness=$ETMI;
	
	//ACTIONABILITY
	// Calculate the normalized ratio (percentage between 0 and 1)
	$ABI = $totalAttributes > 0 ? $toIdsCount / $totalAttributes : 0;
	//echo "$toIdsCount 'to_ids' elements found with value 1 out of $totalAttributes 'Attribute' elements. Normalized ratio: $ABI<br>";
	
	// Define threat level mapping within the function
	$threatLevelMapping = [1 => 1, 2 => 0.6, 3 => 0.3, 0 => 0];
	//echo "Threat Level ID: " . ($threatLevelId ?? "Not Found") . " ";
	$TAI1 = isset($threatLevelMapping[$threatLevelId]) ? $threatLevelMapping[$threatLevelId] : $threatLevelMapping[0];
	//echo "Normalized Threat Level (0 to 1 scale): $TAI<br>";
	$TAI2=($tagCount > 0) ? min(1, ($mitreReference + $threatActor) / $tagCount) : 0;
	$TAI=($TAI1+$TAI2)/2;
	$actionability = ($ABI+$TAI)/2;
	
	//RELIABILITY
	$CCI = $totalAttributes > 0 ? 1-($deletedCount / $totalAttributes) : 0;
	//echo "$deletedCount 'deleted' elements found with value 1 out of $totalAttributes 'Attribute' elements. Normalized ratio: $CCI<br>";
	$reliability=$CCI;
	
	//ACCURACY
	$analysisLevelMapping = [2 => 1, 1 => 0.5, 0 => 0];
	//echo "Analysis Level : " . ($analysisLevel ?? "Not Found") . " ";
	$CAI = isset($analysisLevelMapping[$analysisLevel]) ? $analysisLevelMapping[$analysisLevel] : $analysisLevelMapping[0];
	//echo "Normalized Analysis Level (0 to 1 scale): $CAI<br>";
	$accuracy=$CAI;
	
	//INTEROPERABILITY
	//echo "Number of Tags: $tagCount" . "<br>";		
	//echo "Mitre Attack Patterns: $mitreReference" . "<br>";
	//echo "Threat Actors: $threatActor" . "<br>";
	// Calculate $INI, emphasizing higher values of contributing variables
	$INI = ($tagCount > 0) ? min(1, ($mitreReference + $threatActor) / $tagCount) : 0;
	$interoperability=$INI;

	$finalArray[$key]['timeliness']=$timeliness;	
	$finalArray[$key]['actionability']=$actionability;
	$finalArray[$key]['reliability']=$reliability;
	$finalArray[$key]['accuracy']=$accuracy;
	$finalArray[$key]['interoperability']=$interoperability;
}

//ENTROPY approach
// Step 1: Gather indicator names dynamically from the finalArray
$indicators = array_keys($finalArray[0]); // Assuming that the finalArray contains feed names as keys and indicators as values.

// Prepare to store normalized data and entropy calculations
$normalizedData = []; // Array to store normalized values for each indicator

// Step 2: Normalize each indicator's values by dividing by the sum of all values of that indicator
foreach ($indicators as $indicator) {
    $values = array_column($finalArray, $indicator); // Get the values for each indicator across all feeds
    $sum = array_sum($values);  // Get the sum of the values for the indicator

    // Prevent division by zero when sum == 0
    foreach ($finalArray as $key => $feed) {
        // Normalize each value by dividing by the sum of the indicator's values
        $normalizedValue = $sum == 0 ? 0 : $feed[$indicator] / $sum;
        // Store normalized value for each indicator
        $normalizedData[$indicator][$key] = $normalizedValue;
    }
}

// Step 3: Calculate entropy for each indicator using the corrected formula
$entropy = [];
$totalFeeds = count($finalArray); // Total number of feeds
$k = 1 / log($totalFeeds); // Normalization factor k using ln(totalFeeds)

foreach ($indicators as $indicator) {
    $indicatorEntropy = 0;
    foreach ($normalizedData[$indicator] as $normalizedValue) {
        if ($normalizedValue > 0) { // We exclude values of zero because ln(0) is undefined
            $indicatorEntropy += $normalizedValue * log($normalizedValue); // Accumulate norm * ln(norm)
        }
    }
    // Apply normalization factor k and negate to match the entropy formula
    $entropy[$indicator] = -$k * $indicatorEntropy;
}

// Step 4: Calculate degree of diversification for each indicator
$diversification = [];
foreach ($entropy as $indicator => $e) {
    $diversification[$indicator] = 1 - $e; // Calculate diversification as 1 - Entropy
}

// Step 5: Calculate weights based on diversification by normalizing each diversification degree
$totalDiversification = array_sum($diversification); // Sum of all diversification values

$weights = [];
foreach ($diversification as $indicator => $div) {
    $weights[$indicator] = $totalDiversification > 0 ? $div / $totalDiversification : 0; // Normalize the weights
}

// Step 6: Calculate the final weighted array by applying the weights to each value in finalArray
$weightedArray = [];

foreach ($finalArray as $key => $feed) {
    foreach ($feed as $indicator => $value) {
        // Multiply each value by its respective weight
        $weightedArray[$key][$indicator] = $value * ($weights[$indicator] ?? 0);
    }
}






///////Charts////////////////////////////////////////////////


// Calculate the weighted values
$weightedArray = [];
foreach ($finalArray as $feed) {
    $weightedFeed = [];
    foreach ($feed as $indicator => $value) {
        $weightedFeed[$indicator] = $value * $weights[$indicator];
    }
    $weightedArray[] = $weightedFeed;
}

// Calculate the sum for each feed
$feedSums = array_map(function($feed) {
    return array_sum($feed);
}, $weightedArray);

// Find min and max sums for normalizing the feed coloring
$minSum = min($feedSums);
$maxSum = max($feedSums);

// Normalize the sum value for the feed coloring (higher sums = lighter blue)
function getFeedColor($sum, $minSum, $maxSum) {
    $normalizedValue = ($sum - $minSum) / ($maxSum - $minSum);
    $normalizedValue = max(0, min(1, $normalizedValue));  // Ensure the value is between 0 and 1
    $r = 0;
    $g = 0;
    $b = intval(255 * $normalizedValue);
    return "rgb(0, 0, $b)";  // Lighter blue for higher sums
}

// Function to get the maximum value dynamically, excluding the "Feed" column
function getMaxValue($weightedArray) {
    $maxValue = 0;
    foreach ($weightedArray as $feed) {
        foreach ($feed as $indicator => $value) {
            if ($value > $maxValue) {
                $maxValue = $value;
            }
        }
    }
    return $maxValue;
}

// Dynamically calculate the maximum value for heatmap cells
$maxCellValue = getMaxValue($weightedArray);

function getCellColor($value, $maxCellValue) {
    if ($value == 0) {
        return "rgb(255, 0, 0)"; // Bright red for zero values
    }

    // Normalize values with a piecewise function
    $normalizedValue = $value / $maxCellValue;

    if ($normalizedValue < 0.1) {
        // For very low values, use a steeper gradient
        $gradient = $normalizedValue * 10; // Scale up for granularity
    } else {
        // For larger values, use a logarithmic scale for smooth transition
        $gradient = log($normalizedValue + 1) / log(2); // Base-2 logarithm
    }

    $gradient = max(0, min(1, $gradient)); // Clamp to range [0, 1]

    // Transition from red (low) to orange-red (mid) to green (high)
    if ($gradient < 0.5) {
        // Transition from red to orange-red
        $r = 255;
        $g = intval(150 * $gradient * 2); // Gradually increase green to orange-red
        $b = 0;
    } else {
        // Transition from orange-red to green
        $r = intval(255 * (1 - $gradient) * 2); // Gradually decrease red
        $g = 255;
        $b = 0;
    }

    return "rgb($r, $g, $b)";
}

// Function to determine if a column should be grayed out based on its weight being very small
function shouldGrayOutColumn($indicator, $weights, $grayThreshold = 1E-10) {
    return $weights[$indicator] <= $grayThreshold;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Heatmap and Stacked Bar Chart</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        table {
            border-collapse: collapse;
            width: 60%;
            margin: 0 auto;
            font-family: Arial, sans-serif;
        }
        th, td {
            padding: 2px;
            text-align: center;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        td {
            font-weight: bold;
        }
        .chart-container {
            width: 80%;
            margin: 40px auto;
        }
        .heatmap-legend {
            width: 50%;
            margin: 0px auto;
            text-align: center;
            font-family: Arial, sans-serif;
            font-size: 14px;
        }
        .gradient-bar {
            height: 20px;
            margin: 10px 0;
            width: 60%;
            margin: 0 auto;
            display: flex;
        }
        .gradient-bar div {
            flex: 1;
            height: 100%;
        }
        .blue-gradient {
            background: linear-gradient(to right, rgb(0, 0, 0), rgb(0, 0, 255));
        }
        .red-green-gradient {
            background: linear-gradient(to right, rgb(255, 0, 0), rgb(255, 165, 0), rgb(0, 255, 0));
        }
    </style>
</head>
<body>

<h2 style="text-align: center;">Heatmap Table and Stacked Bar Chart</h2>

<!-- Heatmap Table -->
<table>
    <thead>
        <tr>
            <th>Feed</th>
            <?php foreach (array_keys($weights) as $indicator): ?>
                <th><?php echo ucfirst($indicator); ?></th>
            <?php endforeach; ?>
        </tr>
    </thead>
	<tbody>
	    <?php foreach ($weightedArray as $feedIndex => $feed): ?>
		<tr>
		    <?php
		        // Get feed sum and the corresponding color for the feed cell
		        $feedSum = $feedSums[$feedIndex];
		        $feedColor = getFeedColor($feedSum, $minSum, $maxSum);
		    ?>

		    <!-- Feed Name and Sum -->
		    <td style="background-color: <?php echo $feedColor; ?>; color: gray;">
		        Feed <?php echo $feedIndex + 1; ?><br>
		        <?php echo number_format($feedSum, 6); ?>
		    </td>

		    <!-- Display Weighted Values and Color them Based on Value -->
		    <?php foreach (array_keys($weights) as $indicator): ?>
		        <?php 
		            // Check if the column should be grayed out
		            $isGray = shouldGrayOutColumn($indicator, $weights);

		            // Get the value for each indicator
		            $value = isset($feed[$indicator]) ? $feed[$indicator] : 0;

		            // Apply enhanced granularity color logic
		            $cellColor = $isGray ? "rgb(200, 200, 200)" : getCellColor($value, $maxCellValue);
		        ?>
		        <td style="background-color: <?php echo $cellColor; ?>;"><?php echo number_format($value, 6); ?></td>
		    <?php endforeach; ?>
		</tr>
	    <?php endforeach; ?>
	</tbody>
</table>

<!-- Heatmap Legend -->
<div class="heatmap-legend">
    Feed Sum (Darker Blue = Lower Sum, Lighter Blue = Higher Sum) <div class="gradient-bar blue-gradient"></div>
    Quality Indicator Value Gradient (Red = Lowest, Green = Highest)
    <div class="gradient-bar red-green-gradient"></div>
</div>

<!-- Stacked Bar Chart -->
<div class="chart-container">
    <canvas id="myChart"></canvas>
</div>

<!-- Radar Chart -->
<div class="chart-container">
    <canvas id="myRadarChart"></canvas>
</div>

<script>
    // Data coming from PHP
    const weightedArray = <?php echo json_encode($weightedArray); ?>;
    const weights = <?php echo json_encode($weights); ?>;
    const feedSums = <?php echo json_encode($feedSums); ?>;
    const minSum = <?php echo $minSum; ?>;
    const maxSum = <?php echo $maxSum; ?>;

    // Labels for each feed (Feed 1, Feed 2, etc.)
    const labels = weightedArray.map((feed, index) => 'Feed ' + (index + 1));

    // Indicator names (keys from the first feed object)
    const indicatorNames = Object.keys(weights);

    // Define fixed colors for stacked bar chart
    const indicatorColors = {
        'timeliness': '#4E8E8A',  // Teal
        'actionability': '#FFA07A',  // Light Salmon
        'reliability': '#3B3B6D',  // Dark Slate Blue
        'accuracy': '#876FD4',  // Purple
        'interoperability': '#ea5545'  // Brown
    };

    // Prepare the data for each indicator
    const datasets = indicatorNames.map(indicator => ({
        label: indicator,
        data: weightedArray.map(feed => feed[indicator]),
        backgroundColor: indicatorColors[indicator], // Use predefined colors for the stacked bars
        borderColor: 'rgba(0,0,0,0.2)',
        borderWidth: 1
    }));

    // Create the stacked bar chart
    const ctx = document.getElementById('myChart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,  // Feed names
            datasets: datasets // Stacked bars for indicators
        },
        options: {
            responsive: true,
            indexAxis: 'y',
            plugins: {
		    legend: {
		        position: 'bottom',
		        labels: {
		            font: {
		                size: 16  // Increase the font size of the legend
		            }
		        }
		    },
                tooltip: {
                    callbacks: {
                        label: function(tooltipItem) {
                            const indicator = tooltipItem.dataset.label;
                            const value = tooltipItem.raw;
                            return `${indicator}: ${value.toFixed(4)}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    stacked: true  // Enable stacking
                },
                y: {
                    beginAtZero: true,
                    stacked: true  // Enable stacking
                }
            }
        }
    });

    // Radar chart data (weights of indicators)
    const radarData = {
        labels: indicatorNames,
        datasets: [{
            label: 'Indicators Weights',
            data: Object.values(weights),  // Use the weights directly for the radar chart
            backgroundColor: 'rgba(54, 162, 235, 0.2)',  // Light blue
            borderColor: 'rgba(54, 162, 235, 1)',  // Blue
            borderWidth: 1
        }]
    };

    // Create the radar chart
    const radarCtx = document.getElementById('myRadarChart').getContext('2d');
	const radarChart = new Chart(radarCtx, {
	    type: 'radar',
	    data: radarData,
	    options: {
		responsive: true,
		maintainAspectRatio: true,  // Maintain aspect ratio for resizing
		aspectRatio: 1.8,          // Adjust the aspect ratio to make the radar chart smaller
		plugins: {
		    legend: {
		        position: 'bottom',
		        labels: {
		            font: {
		                size: 16  // Increase font size of the legend
		            }
		        }
		    }
		},
		scales: {
		    r: {
		        angleLines: {
		            display: true, // Ensure lines from the center to each axis are visible
		            lineWidth: 1
		        },
		        ticks: {
		            beginAtZero: true,
		            font: {
		                size: 16
		            }
		        },
		        pointLabels: {
		            font: {
		                size: 20,  // Increase font size for radar point labels
		                family: 'Arial',
		                weight: 'bold'
		            }
		        }
		    }
		}
	    }
	});
</script>

</body>
</html>



<pre>
<?php
print_r($finalArray);
print_r($weights);
print_r($weightedArray);
?>
</pre>


