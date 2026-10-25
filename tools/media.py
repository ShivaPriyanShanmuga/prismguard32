"""Project-native diagrams/caption cards plus a local captioned walkthrough.
Uses installed Pillow, .NET Charting and ffmpeg; downloads nothing.
"""
from pathlib import Path
import json
import shutil
import subprocess
from PIL import Image,ImageDraw,ImageFont

ROOT=Path(__file__).resolve().parents[1]
MEDIA=ROOT/'media';BUILD=ROOT/'build'/'media'
NAVY='#081322';PANEL='#102237';WHITE='#e7f1fa';GREY='#9aafc4';GREEN='#71edbb';GOLD='#edc47b'
FONTS=Path('C:/Windows/Fonts')

def font(size,bold=False,mono=False):return ImageFont.truetype(str(FONTS/('consola.ttf' if mono else 'segoeuib.ttf' if bold else 'segoeui.ttf')),size)
def wrap(draw,text,fnt,width):
    result=[]
    for paragraph in text.split('\n'):
        line=''
        for word in paragraph.split():
            test=(line+' '+word).strip()
            if draw.textlength(test,font=fnt)>width and line:result.append(line);line=word
            else:line=test
        result.append(line)
    return result
def base(i,kicker,title):
    im=Image.new('RGB',(1280,720),NAVY);d=ImageDraw.Draw(im)
    d.rounded_rectangle((48,36,1232,684),radius=22,fill=PANEL)
    d.text((84,63),'PRISMGUARD / 32',font=font(22,True),fill=GREEN)
    d.text((1080,65),f'{i:02d}/09',font=font(18,mono=True),fill=GREY)
    d.text((84,120),kicker.upper(),font=font(16,True),fill=GOLD)
    d.text((84,162),title,font=font(44,True),fill=WHITE)
    d.line((84,233,1196,233),fill='#2d4660',width=2)
    d.text((84,644),'Research prototype | synthetic data | captioned walkthrough | Cryptographer track',font=font(17),fill=GREY)
    return im,d
def paragraphs(d,items,size=25,y=268):
    for text,color in items:
        for line in wrap(d,text,font(size),1090):d.text((84,y),line,font=font(size),fill=color);y+=size+9
        y+=18
    assert y<636,('caption overflow',y)

def main():
    MEDIA.mkdir(exist_ok=True);BUILD.mkdir(exist_ok=True)
    report=json.loads((ROOT/'evidence'/'verification.json').read_text(encoding='utf-8'))
    pictures=[];speeches=[]
    def add(im,speech):pictures.append(im);speeches.append(speech)
    im,d=base(1,'A protected-computation case study','Keep the secret in shares.')
    paragraphs(d,[('32-byte master key -> 104-byte authenticated capsule',GREEN),
                  ('Masked arithmetic, a controlled release boundary, and recovery after hostile packets.',WHITE),
                  ('An executable attack laboratory accompanies the mathematical argument.',WHITE),
                  ('No real credentials. No user-file encryption. No system changes.',GREY)])
    add(im,'PrismGuard thirty two is a masked master key capsule and recovery laboratory. The project keeps private arithmetic in shares and demonstrates both protection and failure cases, using only synthetic data.')
    im,d=base(2,'The improvement over PrismLock-32','A stronger security experiment')
    paragraphs(d,[('Raw private arithmetic -> randomized two-share operations',GREEN),
                  ('One bad packet ends recovery -> up to eight bounded attempts',WHITE),
                  ('Raw tag comparison -> shared zero tests, one public decision bit',WHITE),
                  ('Positive tests alone -> exact model, attacks, and negative controls',GREY)])
    add(im,'The improvement is concrete. Private nonlinear operations stay shared. Tag verification releases only its final decision. A receiver can reject seven hostile packets and still accept a genuine eighth packet.')
    im,d=base(3,'Number theory + linear algebra','A short confidentiality argument')
    paragraphs(d,[('p = 2^61 - 1     A = I + 11^T',GREEN),
                  ('c = A ((A m + r)^[17])',WHITE),
                  ('Fresh uniform translation and public bijections give an identical public distribution for every message.',WHITE),
                  ('The matrix and power layers add no entropy. The one-use mask supplies secrecy.',GREY)])
    add(im,'The capsule works over a Mersenne prime field. A fresh mask, matrix, and coordinate power produce the ciphertext. Public transformations add no entropy. Confidentiality depends on independent one-use material.')
    im,d=base(4,'Protected multiplication and verification','Do not unshare to check.')
    paragraphs(d,[('x = xL + xR mod p; refresh before private binary operations',GREEN),
                  ('Refresh both inputs even for squaring. Mask cross-term accumulation before combining it.',WHITE),
                  ('Compute tag-difference zero tests in shares. Release only the combined rejection bit.',WHITE),
                  ('Trusted ingress and authorized plaintext release are explicit boundaries.',GREY)],size=24)
    add(im,'Each private value is represented by two randomized field shares. The multiplier refreshes both operands, including squaring. Authentication differences remain shared. Only the final rejection bit is exposed before authenticated recovery.')
    for index,mode,speech in [
        (5,'safe','This exact small-field experiment checks nineteen multiplier wires across every pair of logical inputs and every randomness assignment. The protected distributions match. Rust and an independent Python model agree.'),
        (6,'unsafe','The negative control deliberately combines cross terms without their random mask. Its distributions differ by total variation zero point two. Observing both shares also reconstructs the result. These excluded attacks are demonstrated, not hidden.')]:
        im=Image.new('RGB',(1280,720),NAVY);d=ImageDraw.Draw(im)
        d.text((80,40),f'PRISMGUARD / 32   |   EXACT SMALL-FIELD MODEL   |   {index:02d}/09',font=font(22,True),fill=GREEN)
        chart=Image.open(MEDIA/f'model-{mode}.png').convert('RGB');im.paste(chart,(80,98))
        d.text((80,681),'F5 multiplier gadget only. Not a whole-program or hardware leakage certificate.',font=font(18),fill=GREY)
        add(im,speech)
    im,d=base(7,'Excerpt of actual captured Rust output','Reject hostile packets. Recover.')
    captured=(ROOT/'evidence'/'demo-output.txt').read_text(encoding='utf-8')
    lines=[line for line in captured.splitlines() if line.startswith(('[1]','[3.1]','[3.2]','[3.3]','[4]','[5]'))]
    y=269
    for line in lines:
        for row in wrap(d,line,font(23,mono=True),1090):d.text((84,y),row,font=font(23,mono=True),fill=GREEN if 'PASS' in row or 'BLOCKED' in row else WHITE);y+=33
        y+=11
    assert y<630
    add(im,'This is actual captured output from the built Rust demonstration. Three modified packets are rejected. The genuine capsule then recovers the exact synthetic key. Replay after successful recovery is blocked.')
    im,d=base(8,'Evidence, not certification','Reproduce the claims.')
    bench=report['benchmark'];medians=[b['median_ns']/1000 for b in bench]
    paragraphs(d,[('14 Rust groups | 512 oracle vectors | 60,000 arithmetic checks',GREEN),
                  ('832 single-bit changes and 2,000 multi-bit mutations rejected; valid recovery afterward.',WHITE),
                  ('Timing tests cover seal, valid open, rejected open, and deliberately leaky controls. Ordered samples are included.',WHITE),
                  (f'Medians: seal {medians[0]:g} us, open {medians[1]:g} us; full OS-RNG workflow {medians[2]:g} us. One machine, one recorded run.',GREY)],size=23)
    add(im,'The package includes fourteen Rust test groups, five hundred twelve independent capsule vectors, and sixty thousand arithmetic checks. Timing diagnostics retain ordered samples and include deliberately leaky controls. Results are machine specific.')
    im,d=base(9,'Review the model before trusting the result','The boundaries are part of the result.')
    paragraphs(d,[('Never reuse logical pad material. Keep provisioning confidential.',GREEN),
                  ('A single field-wire model does not establish protection against multiple probes, physical leakage, register transitions, a compromised OS, or rollback.',WHITE),
                  ('Established techniques are credited. AI assistance is disclosed. No independent human audit has occurred.',WHITE),
                  ('Research prototype: source, compiled LaTeX, raw evidence, and reproducible commands accompany the entry.',GREY)],size=23)
    add(im,'The boundaries matter. Logical pads must never be reused. This is not a physical side-channel certificate or an independently audited product. Established techniques are credited, and AI assistance is disclosed. The source and evidence support review.')
    for i,im in enumerate(pictures):im.save(MEDIA/f'walkthrough-{i+1:02d}.png')
    thumb=Image.new('RGB',(1200,800),NAVY);d=ImageDraw.Draw(thumb)
    d.text((78,74),'PRISMGUARD / 32',font=font(38,True),fill=GREEN)
    d.text((78,190),'Keep the key',font=font(76,True),fill=WHITE)
    d.text((78,285),'in shares.',font=font(76,True),fill=WHITE)
    d.text((78,430),'Masked computation. Bounded recovery.',font=font(34),fill=WHITE)
    d.text((78,493),'An executable adversarial laboratory.',font=font(34),fill=GREY)
    d.line((78,596,1122,596),fill='#2d4660',width=2)
    d.text((78,637),'Rust | finite fields | exact probing experiments',font=font(27),fill=GREEN)
    d.text((78,706),'Cryptographer track - research prototype',font=font(24),fill=GREY)
    thumb.save(MEDIA/'cover-3x2.png')
    contact=Image.new('RGB',(1280,720),NAVY)
    for i,im in enumerate(pictures):contact.paste(im.resize((426,240)),((i%3)*426,(i//3)*240))
    contact.save(MEDIA/'contact-sheet.png')
    segments=[{'id':f'scene-{i+1:02d}','speech':speech} for i,speech in enumerate(speeches)]
    (MEDIA/'narration.json').write_text(json.dumps(segments,indent=2)+'\n',encoding='utf-8')
    ffmpeg=shutil.which('ffmpeg');ffprobe=shutil.which('ffprobe')
    if not ffmpeg or not ffprobe:raise RuntimeError('Installed ffmpeg/ffprobe required; no download attempted')
    concat=MEDIA/'frames.ffconcat'
    concat.write_text('ffconcat version 1.0\n'+''.join(f"file 'walkthrough-{i+1:02d}.png'\nduration 15\n" for i in range(9))+"file 'walkthrough-09.png'\n",encoding='ascii')
    out=MEDIA/'PrismGuard-32-walkthrough.mp4'
    subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-y','-f','concat','-safe','1','-i',str(concat),'-t','135','-vf','fps=12,format=yuv420p','-c:v','libx264','-preset','fast','-crf','20','-movflags','+faststart',str(out)],check=True)
    result={'video':out.name,'scenes':9,'duration_seconds_approx':135,
            'narration':'silent captioned walkthrough; optional narration script was blocked by local policy; policy unchanged',
            'terminal_scene':'excerpt of actual captured demo-output.txt','all_inputs_local':True}
    (MEDIA/'media-report.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))

if __name__=='__main__':main()
