rule Win_Trojan_Agent_33324
{
strings:
	$a0 = { ca6ebbabd727833423f74073a2b0fad8506a903770b7a577f1fabdd7c3832f0d509e979c7cb9a8ba20125d40faadeb5da781b9160348a70040c65b6a9024cf0d9b2d3f3a52ce760decd76ef0f27304f23a6656ad8d4716551df1a8ac8af0 }

condition:
	$a0
}

        
