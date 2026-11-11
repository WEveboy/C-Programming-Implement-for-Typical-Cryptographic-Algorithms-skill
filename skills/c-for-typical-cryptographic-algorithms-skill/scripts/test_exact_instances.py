"""Independent frozen finite arithmetic and rejection tests for exact_instance.py."""
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUBJECT = ROOT / 'scripts/exact_instance.py'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan():
    cases = []
    normals = [
        ({'algorithm':'rsa','p':5,'q':11,'e':3,'message':7},
         {'n':55,'d':27,'ciphertext':13,'recovered':7}),
        ({'algorithm':'paillier','p':3,'q':5,'g':16,'message':7,'r':2},
         {'n':15,'ciphertext':83,'recovered':7}),
        ({'algorithm':'mh','private':[2,5,11,23],'modulus':47,'multiplier':3,'bits':[1,0,1,1]},
         {'public':[6,15,33,22],'ciphertext':61,'recovered':[1,0,1,1],'remaining':0}),
        ({'algorithm':'elgamal','p':23,'g':5,'private':6,'nonce':7,'message':4},
         {'public':8,'ciphertext':[17,2],'recovered':4}),
        ({'algorithm':'ecc','p':17,'a':2,'b':2,'point':[5,1],'scalar':3},
         {'point':[10,6]}),
        ({'algorithm':'ntru','p':3,'q':17,'f':[1,0,0],'g':[0,1,-1],
          'fp':[1,0,0],'fq':[1,0,0],'r':[1,0,0],'message':[1,-1,0]},
         {'public':[0,1,16],'ciphertext':[1,2,14],'centered':[1,2,-3],'recovered':[1,2,0]}),
        ({'algorithm':'mceliece-toy','generator':[[1,1,1]],'ciphertext':[1,0,1],'t':1},
         {'message':[1],'codeword':[1,1,1],'minimum_distance':3}),
    ]

    def add(case_id, data, expected=None, kind='boundary'):
        cases.append({'id':case_id,'kind':kind,'input':data,
                      'expected_exit':0 if expected is not None else 2,
                      'expected':{'status':'ok','result':expected} if expected is not None else {'status':'rejected','reason_nonempty':True}})

    for data, expected in normals:
        alg = data['algorithm']
        add(alg+'-new-normal',data,expected,'normal-new-input')
        for key, value in data.items():
            if key == 'algorithm':
                continue
            if type(value) is int:
                for label, bad in [('bool',True),('float',1.0),('string','1'),('null',None),('array',[]),('object',{})]:
                    new=copy.deepcopy(data);new[key]=bad
                    add(f'{alg}-{key}-type-{label}',new,kind='scalar-type-rejection')
            elif isinstance(value,list) and key != 'generator':
                # null is a valid ECC infinity, and tested separately below.
                wrongs=[('string','01'),('object',{}),('empty',[]),('long',[0]*33)]
                if key != 'point': wrongs.append(('null',None))
                for label,bad in wrongs:
                    new=copy.deepcopy(data);new[key]=bad
                    add(f'{alg}-{key}-vector-{label}',new,kind='vector-shape-rejection')
                for label,bad in [('bool',True),('float',1.0),('string','1'),('null',None),('array',[]),('object',{})]:
                    new=copy.deepcopy(data);new[key][0]=bad
                    add(f'{alg}-{key}-coefficient-{label}',new,kind='coefficient-type-rejection')
        for key in data:
            if key != 'algorithm':
                new=copy.deepcopy(data);del new[key]
                # Paillier g is optional and has separate result equivalence check.
                if alg=='paillier' and key=='g':add(alg+'-default-g',new,expected,'optional-field')
                else:add(f'{alg}-missing-{key}',new,kind='missing-field')

    def change(i, case_id, expected=None, **updates):
        data=copy.deepcopy(normals[i][0]);data.update(updates);add(case_id,data,expected)

    change(0,'rsa-e-nonunit',e=4)
    change(0,'rsa-m-out-of-range',message=55)
    change(0,'rsa-composite',p=9)
    change(0,'rsa-equal-primes',q=5)
    change(0,'rsa-nonunit-message',{'n':55,'d':27,'ciphertext':10,'recovered':10},message=10)
    change(1,'paillier-r-nonunit',r=3)
    change(1,'paillier-g-invalid-L',g=1)
    change(1,'paillier-m-out-of-range',message=15)
    change(1,'paillier-even-prime',p=2)
    change(2,'mh-nonsuperincreasing',private=[2,3,4,23])
    change(2,'mh-small-modulus',modulus=41)
    change(2,'mh-nonunit-multiplier',modulus=45,multiplier=3)
    change(2,'mh-nonbinary',bits=[1,0,2,1])
    change(3,'elgamal-subgroup-generator',g=4)
    change(3,'elgamal-zero-message',message=0)
    change(3,'elgamal-zero-nonce',nonce=0)
    change(4,'ecc-invalid-point',point=[5,2])
    change(4,'ecc-singular',a=0,b=0)
    change(4,'ecc-infinity',{'point':None},point=None,scalar=(1<<32)-1)
    change(4,'ecc-zero-scalar',{'point':None},scalar=0)
    change(4,'ecc-y-zero-doubling',{'point':None},a=1,b=0,point=[0,0],scalar=2)
    change(5,'ntru-bad-fp',fp=[0,0,0])
    change(5,'ntru-vector-mismatch',r=[1,0])
    change(5,'ntru-wrap',r=[10,0,0])
    change(5,'ntru-q-budget',q=65536)
    change(6,'mceliece-rank',generator=[[1,1,1],[1,1,1]])
    change(6,'mceliece-distance',t=2)
    change(6,'mceliece-cipher-nonbinary',ciphertext=[1,2,1])
    change(6,'mceliece-matrix-nonbinary',generator=[[1,2,1]])
    for label,bad in [('bool',True),('float',1.0),('string','1'),('null',None),('array',[]),('object',{})]:
        change(6,'mceliece-matrix-coefficient-'+label,generator=[[bad,1,1]])
    for label,bad in [('null',None),('string','111'),('object',{}),('empty',[]),('k-budget',[[1,1,1]]*11),('invalid-row',[None]),('long-row',[[1]*33])]:
        change(6,'mceliece-matrix-'+label,generator=bad)
    add('unknown-algorithm',{'algorithm':'not-implemented'})
    add('missing-algorithm',{})
    for label,bad in [('array',[]),('null',None),('string','rsa'),('integer',1),('bool',True)]:
        add('root-'+label,bad)
    return cases


def main():
    cases=plan()
    task=ROOT/'evaluation/tasks/exact-agent-cases.json';task.parent.mkdir(parents=True,exist_ok=True)
    frozen={'schema_version':1,'provenance':'Independently chosen synthetic inputs and expected values, frozen before subject execution; no other evaluation expected files read.',
            'oracle':'Manual modular arithmetic, independently checked integer pow, repeated point addition, identity-f polynomial ring and repetition-code decoding.',
            'cases':cases}
    task.write_text(json.dumps(frozen,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    results=[]
    for case in cases:
        proc=subprocess.run([sys.executable,str(SUBJECT)],input=json.dumps(case['input']),capture_output=True,text=True,timeout=10)
        try:actual=json.loads(proc.stdout)
        except ValueError:actual={'invalid_json_output':proc.stdout}
        expected=case['expected']
        matched=(actual==expected if expected['status']=='ok' else actual.get('status')=='rejected' and isinstance(actual.get('reason'),str) and bool(actual['reason']))
        results.append({'id':case['id'],'kind':case['kind'],'actual':actual,'expected':expected,
                        'exit_code':proc.returncode,'expected_exit':case['expected_exit'],
                        'stderr':proc.stderr,'passed':proc.returncode==case['expected_exit'] and matched and not proc.stderr})
    result={'schema_version':1,'execution_mode':'actual_execution','scope':'Independent finite arithmetic and CLI type/domain/budget rejection; not full cryptographic schemes or host loading.',
            'planned':len(cases),'completed':len(results),'passed':sum(x['passed'] for x in results),
            'subject_sha256':digest(SUBJECT),'test_script_sha256':digest(Path(__file__)),
            'frozen_plan_sha256':digest(task),'python':sys.version,'results':results}
    out=ROOT/'evaluation/reports/exact-agent-review.json';out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['results','python']},ensure_ascii=False))
    failures=[x for x in results if not x['passed']]
    if failures:print(json.dumps(failures,ensure_ascii=False,indent=2))
    return bool(failures)


if __name__=='__main__':
    sys.exit(main())
