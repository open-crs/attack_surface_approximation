"""Package for discovering the attack surface of an executable."""
from attack_surface_approximation.exceptions import InputStreamsDetectorException
from attack_surface_approximation.input_streams import (
    InputStreamsDetector,
    PresentInputStreams,
)
