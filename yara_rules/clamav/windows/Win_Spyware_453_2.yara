rule Win_Spyware_453_2
{
strings:
	$a0 = { d8ca61804dc1d9e19a7a1569735c8bd9dc5aac13d7b716f08b7ebde46d35ab4452b1c21fb07a1c7d6eb771fc4eb25caea627b08ec728c21d9fb5dc29e9355dba6259829bca3f5fa2d3b38dc4ea5d2c9ba1f1ae16bf745b2587e0a114fb62cc23fcf6b9dd56cf2f73dca6f4ad2adc0b5d2cecbd2ea2b80fa3c853f32f7d75b5c6 }

condition:
	$a0
}

        
