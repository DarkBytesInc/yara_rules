rule Win_Spyware_Banker_1185
{
strings:
	$a0 = { de158ff1259010ea84f926df7eb9259912e9a599e0b0e9f7b7b83e78201c9e9e6d5f3bb831b96dcdd8c8454916b6a5f6a22089b83a59358f533066c14649db058260a33caef840b7b8dbd33200d72f5f2eabfdf6396206471a10dfd03da18b39b4cbd92e829e8d4787b32a0fd4123146267eabb2225e }

condition:
	$a0
}

        