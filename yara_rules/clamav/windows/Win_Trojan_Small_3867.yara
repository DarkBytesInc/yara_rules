rule Win_Trojan_Small_3867
{
strings:
	$a0 = { 2b1753f03bffdedf9ad94dfbbe96172ac8d6d3df9adc4d13bfa2192299894be3be9640e11f6237dd27d5c5f0048fc174eb85d8f3abc6c22a930cc213c41319a0ecd9199eb0c6d3df9af0c3f5edee82bcda86aadb8c86c2225f9719099b8598ef999c12afda862a63 }

condition:
	$a0
}

        
