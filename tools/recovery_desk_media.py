"""Narrated application addendum using captured output and verified evidence.
Uses the same optional project-local neural voice client; original video kept.
"""
from pathlib import Path
import json
from PIL import Image,ImageDraw
import narrated_video as maker
import media as cards

ROOT=Path(__file__).resolve().parents[1]
maker.BUILD=ROOT/'build'/'recovery-desk-media'
maker.OUT=ROOT/'media'/'recovery-desk'
maker.VIDEO_NAME='PrismGuard-Recovery-Desk-demo.mp4'
maker.DEMO_TITLE='PrismGuard Recovery Desk application demonstration'
maker.SCOPE='Narrated application addendum with actual captured application output; not a continuous screen recording.'
maker.SCENES=[
    ('A recovered key that does something',
     'The recovery desk gives the protected key a real application job. '
     'A fresh signing key is wrapped in a Prism Guard capsule. '
     'After authenticated recovery, it signs a synthetic training access pass. '
     'A separate controller verifies that pass using only the public key.'),
    ('Recovery gates the signing operation',
     'This is actual captured output from the application. '
     'Issuing a pass before recovery is denied. '
     'Three altered capsules are rejected, and signing stays locked. '
     'The genuine capsule then restores the signing key and makes the desk ready to issue one pass.'),
    ('The controller makes a verified decision',
     'The recovered key now performs a real signature operation through Windows. '
     'An altered signature and a wrong resource are rejected. '
     'The genuine signed pass grants one synthetic request. '
     'Replaying the pass, or asking the desk for another signature, is blocked.'),
    ('Independent application evidence',
     'Twenty six combined Rust test groups pass. '
     'Python independently verifies thirty two fresh public signatures and their alternate valid encodings. '
     'The controller tracks the challenge rather than signature bytes, so changing the signature encoding cannot produce another grant. '
     'The interactive application is tested as well.'),
    ('The application boundary is explicit',
     'Prism Guard encrypts the key. Windows provides the established signature operation after authorized recovery. '
     'That provider is outside the capsule leakage proof. '
     'All data and grants are synthetic, and all roles currently share one process. '
     'No real file, credential, device permission, or account is affected.'),
]

def base(index,kicker,title):
    image=Image.new('RGB',(1280,720),cards.NAVY);draw=ImageDraw.Draw(image)
    draw.rounded_rectangle((48,36,1232,684),radius=22,fill=cards.PANEL)
    draw.text((84,63),'PRISMGUARD / RECOVERY DESK',font=cards.font(22,True),fill=cards.GREEN)
    draw.text((1080,65),f'{index:02d}/05',font=cards.font(18,mono=True),fill=cards.GREY)
    draw.text((84,120),kicker.upper(),font=cards.font(16,True),fill=cards.GOLD)
    draw.text((84,162),title,font=cards.font(42,True),fill=cards.WHITE)
    draw.line((84,233,1196,233),fill='#2d4660',width=2)
    draw.text((84,644),'Applicable environment | real signatures | synthetic training access | Windows Rust',font=cards.font(17),fill=cards.GREY)
    return image,draw

def captured(draw,lines):
    y=270
    for line in lines:
        for row in cards.wrap(draw,line,cards.font(21,mono=True),1090):
            draw.text((84,y),row,font=cards.font(21,mono=True),fill=cards.GREEN if any(word in row for word in ['DENIED','REJECTED','BLOCKED','GRANTED','READY']) else cards.WHITE)
            y+=29
        y+=15
    assert y<636,('application card overflow',y)

def render():
    report=json.loads((ROOT/'evidence'/'recovery-desk'/'verification.json').read_text())
    assert report['public_passes_independently_verified']==32
    output=(ROOT/'evidence'/'recovery-desk'/'demo-output.txt').read_text().splitlines()
    pictures=[]
    image,draw=base(1,'From capsule to an actual protected action','Recover. Sign. Verify. Grant once.')
    cards.paragraphs(draw,[
        ('A 32-byte private signing scalar is protected by PrismGuard.',cards.GREEN),
        ('The recovered key signs a fresh, resource-bound training request.',cards.WHITE),
        ('The controller holds only the public key. It verifies the signature before changing application state.',cards.WHITE),
        ('Offline Rust application; no real files, credentials, doors or accounts.',cards.GREY)],size=24)
    pictures.append(image)
    image,draw=base(2,'Actual captured recovery-desk.exe output','Recovery gates the signing operation.')
    captured(draw,[line for line in output if line.startswith(('[2]','[3.1]','[3.2]','[3.3]','[4]'))]);pictures.append(image)
    image,draw=base(3,'Actual captured application output','Public-key verification grants access.')
    captured(draw,[line for line in output if line.startswith(('[5]','[6]','[7]','[8]','[9]'))]);pictures.append(image)
    image,draw=base(4,'Evidence includes attacks on the application','A pass is checked independently.')
    cards.paragraphs(draw,[
        ('26 combined Rust groups: 14 core + 12 application tests',cards.GREEN),
        ('32 fresh public passes verified independently with Python big integers.',cards.WHITE),
        ('Alternate valid ECDSA encodings are also checked. Consumed challenges block a second grant.',cards.WHITE),
        ('Wrong key, context, resource, nonce, signature, premature issuance and replay are tested.',cards.GREY)],size=24)
    pictures.append(image)
    image,draw=base(5,'Explicit scope and trusted boundaries','A practical research prototype.')
    cards.paragraphs(draw,[
        ('PrismGuard encrypts the key; CNG consumes it after authorized release.',cards.GREEN),
        ('Established ECDSA signatures are credited. Provider leakage is outside the capsule proof.',cards.WHITE),
        ('One process, synthetic grants, trusted provisioning. No durable rollback ledger or physical controller is claimed.',cards.WHITE),
        ('Original core sources and the prior demonstrations are preserved.',cards.GREY)],size=24)
    pictures.append(image)
    for i,image in enumerate(pictures,1):image.save(maker.BUILD/f'scene-{i:02d}.png')
    pictures[0].save(maker.OUT/'poster.png')
    contact=Image.new('RGB',(1280,720),cards.NAVY)
    for i,image in enumerate(pictures):contact.paste(image.resize((426,240)),((i%3)*426,(i//3)*240))
    contact.save(maker.OUT/'contact-sheet.png')

maker.render=render
if __name__=='__main__':maker.main()
