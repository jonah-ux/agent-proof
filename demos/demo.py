import tempfile,pathlib
from agent_proof.cli import main
with tempfile.TemporaryDirectory() as d:
 print('Agent Proof demo: capture first, claim later')
 main(['capture','--out',str(pathlib.Path(d)/'proof.json')])
