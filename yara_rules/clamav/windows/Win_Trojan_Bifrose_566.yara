rule Win_Trojan_Bifrose_566
{
strings:
	$a0 = { 3953584a29dc423dc0cca2b04c2783afb8c02f4b9ca6cf25569a258b8e3740ab34999d4f1f6ad4417afcc1d9a06ace0b8ed268a2cdf5e37f16b3e2a8bb9094cf93b5188f27ba1f7cadbccbc14ac259e321b405ddb4f091a5171c30c55219774e19e41ee762866d463f6d7210b58e5a32ed60a81fa195a3991951ff4fa837dc8b91981217b307409a4285ff49337255fc68104b8513cf }

condition:
	$a0
}

        