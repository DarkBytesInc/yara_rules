rule Win_Dropper_Agent_33517
{
strings:
	$a0 = { 2184b659ed4b78ed524c501b5ebc533e57da665c1883b32e8b227d4d6dab0d9136e40d0cdb1af90d56e5ff86655224671f2b2d3f971efbd61c37fc30a4f67c5552bf33fd599a0c787ee17c77cbd728ef57727aed }

condition:
	$a0
}

        
