import unittest
from agent_proof.cli import main
class Smoke(unittest.TestCase):
    def test_import(self): self.assertTrue(callable(main))
if __name__=="__main__": unittest.main()
