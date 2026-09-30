import argparse,hashlib,json,pathlib

def main(argv=None):
 p=argparse.ArgumentParser(prog='agent-proof'); p.add_argument('command',choices=['capture','verify']); p.add_argument('path',nargs='?'); p.add_argument('--out',default='proof.json'); a=p.parse_args(argv)
 if a.command=='capture':
  d={'schema':'agent-proof/v1','observed':False,'commands':[],'artifacts':[],'notes':['Capture records evidence; it does not claim a user-visible result.']}
  if a.path: d['source']=str(pathlib.Path(a.path).resolve())
  raw=json.dumps(d,sort_keys=True,separators=(',',':')); d['sha256']=hashlib.sha256(raw.encode()).hexdigest(); pathlib.Path(a.out).write_text(json.dumps(d,indent=2,sort_keys=True)+'\n'); print(json.dumps(d,indent=2,sort_keys=True)); return 0
 d=json.load(open(a.path or a.out)); ok=d.get('schema')=='agent-proof/v1' and bool(d.get('sha256')) and bool(d.get('observed')); print(json.dumps({'schema':'agent-proof/verify/v1','ok':ok,'reason':'observed result required' if not ok else 'verified'},indent=2)); return 0 if ok else 1
