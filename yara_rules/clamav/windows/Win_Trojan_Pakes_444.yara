rule Win_Trojan_Pakes_444
{
strings:
	$a0 = { fda2497381f903c74429ef927a8d1f0a7d462f0499ba735a7dae338be0b0e9d4665f2996268fe1278ab9e88ffab8419d71eef3afc705eb996afb57914b54ecef5eb32cb67aaedc0aa9b31b5c0be5faaca4fee71b7044f4a1bd0e293e968f6f63f5b3d4830b09ab5e6a5bff8497224d02fdeb4fe3d3374236262be1ca89b1e0b7db1354f9ccad3490c3327893 }

condition:
	$a0
}

        