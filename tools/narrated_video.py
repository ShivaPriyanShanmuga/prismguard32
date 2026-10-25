"""Create a narrated demonstration from public synthetic project material.

Optional media tool: uses project-local edge-tts and installed Pillow/ffmpeg.
Only the text below is sent to Microsoft's online speech service. No keys,
browser data or credentials are read. The original silent video is retained.
"""
from pathlib import Path
import asyncio
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT/'build'/'narrated'
OUT = ROOT/'media'/'narrated'
sys.path.insert(0, str(ROOT/'build'/'narration-deps'))
import edge_tts
import media as cards
from PIL import Image, ImageDraw

VOICE = 'en-US-AndrewMultilingualNeural'
RATE = '+5%'
LEAD = .35
TAIL = .85
SCENES = [
    ('A masked master-key capsule',
     'Prism Guard thirty two is a master key capsule and recovery laboratory. '
     'It wraps a synthetic thirty two byte key in an authenticated capsule. '
     'This demonstration uses no real credentials or user files.'),
    ('Bounded recovery',
     'The receiver can reject seven hostile packets and still recover from a genuine eighth packet. '
     'An eighth failure locks the receiver. After successful recovery, the receiver refuses further attempts. '
     'This makes both the recovery policy and its availability limit explicit.'),
    ('Number theory and linear algebra',
     'The construction uses a prime equal to two to the power of sixty one, minus one. '
     'An invertible matrix and a coordinate power transform the masked key. '
     'Fresh, independent, one use secret material supplies confidentiality. '
     'The public transformations do not add cryptographic hardness.'),
    ('Protected computation',
     'Private field values stay in two randomized shares. '
     'Both operands are independently refreshed before multiplication, including when a value is squared. '
     'Authentication differences also stay shared. Verification releases only its final decision, '
     'and plaintext is released only after authentication succeeds.'),
    ('Exact small-field experiment',
     'The exact small field experiment observes nineteen wires in the multiplier. '
     'Every logical input pair and every random assignment is checked. '
     'The protected wire distributions match across secret inputs. '
     'The same generic Rust schedule is used in production, and Python independently checks the experiment.'),
    ('A control that deliberately leaks',
     'The deliberately unsafe control combines cross terms without their random mask. '
     'Its distributions differ by total variation zero point two, so this experiment detects the intended leak. '
     'Observing both output shares also reconstructs the product. '
     'That attack lies outside the single wire protection model.'),
    ('Actual captured demonstration output',
     'This is an excerpt of actual captured Rust output. '
     'Three altered packets are rejected. The genuine capsule then recovers exactly the synthetic key. '
     'A replay after successful recovery is blocked. '
     'This is captured output presented as a walkthrough, rather than a continuous screen recording.'),
    ('Additional adversarial evidence',
     'The suite includes fourteen Rust test groups and an independent capsule oracle. '
     'An additional eighty one thousand two hundred and fifty executions test correlated shares and squaring. '
     'Those distributions match, while omitting independent refresh exposes a measurable leak. '
     'Timing diagnostics retain raw measurements and deliberately leaky controls.'),
    ('Security boundaries',
     'The limits matter. Never reuse logical pad material, and keep provisioning confidential. '
     'These arithmetic experiments are not a physical side channel certificate or an independent cryptographic audit. '
     'Multiple probes, power measurements, a compromised operating system, and rollback remain outside the established result. '
     'The source, mathematical paper, and reproducible evidence are available for review.'),
]

def run(args):
    return subprocess.check_output(args, cwd=ROOT, text=True, encoding='utf-8', errors='replace')

def probe(path):
    return json.loads(run(['ffprobe', '-v', 'error', '-show_format', '-show_streams', '-of', 'json', str(path)]))

def stamp(seconds):
    millis = round(seconds*1000)
    h, millis = divmod(millis, 3600000); m, millis = divmod(millis, 60000)
    s, ms = divmod(millis, 1000)
    return f'{h:02d}:{m:02d}:{s:02d},{ms:03d}'

async def synthesize():
    for i, (_, speech) in enumerate(SCENES, 1):
        name = f'scene-{i:02d}'
        audio, meta, receipt = BUILD/f'{name}.mp3', BUILD/f'{name}.jsonl', BUILD/f'{name}-receipt.json'
        requested = {'text': speech, 'voice': VOICE, 'rate': RATE, 'edge_tts': edge_tts.__version__}
        if receipt.exists() and json.loads(receipt.read_text()) == requested and audio.exists() and meta.exists():
            print(f'Reusing verified narration {i}/9.', flush=True)
            continue
        print(f'Generating narration {i}/9...', flush=True)
        await edge_tts.Communicate(speech, VOICE, rate=RATE, boundary='WordBoundary').save(str(audio), str(meta))
        assert audio.stat().st_size > 10000
        receipt.write_text(json.dumps(requested, indent=2)+'\n', encoding='utf-8')

def render():
    for i in range(1, 10):
        shutil.copyfile(ROOT/'media'/f'walkthrough-{i:02d}.png', BUILD/f'scene-{i:02d}.png')
    image, draw = cards.base(8, 'Evidence that includes failure cases', 'Reproduce the security experiment.')
    cards.paragraphs(draw, [
        ('14 Rust test groups | 512 independent capsule vectors', cards.GREEN),
        ('81,250 additional correlated-share and squaring executions in each of Rust and Python. Zero distribution mismatches.', cards.WHITE),
        ('Omitting independent refresh leaks: exact total-variation distance 0.60 in the small-field control.', cards.WHITE),
        ('Retained timing samples and deliberately leaky controls. Gadget evidence, not a hardware certificate.', cards.GREY)
    ], size=23)
    image.save(BUILD/'scene-08.png')
    # A recognisable, clickable poster for the README and local previews.
    poster = Image.open(ROOT/'media'/'cover-3x2.png').convert('RGB')
    overlay = ImageDraw.Draw(poster)
    overlay.rounded_rectangle((826, 585, 1125, 657), radius=15, fill=cards.GREEN)
    overlay.polygon([(852,604),(852,639),(881,621)], fill=cards.NAVY)
    overlay.text((901,600), 'WATCH DEMO', font=cards.font(25,True), fill=cards.NAVY)
    poster.save(OUT/'poster.png')

def main():
    assert shutil.which('ffmpeg') and shutil.which('ffprobe')
    BUILD.mkdir(parents=True, exist_ok=True); OUT.mkdir(parents=True, exist_ok=True)
    asyncio.run(synthesize())
    render()
    elapsed, subtitle_id, captions, chapters = 0.0, 0, [], []
    records = []
    for i, (title, speech) in enumerate(SCENES, 1):
        audio = BUILD/f'scene-{i:02d}.mp3'
        spoken = float(probe(audio)['format']['duration'])
        duration = math.ceil((LEAD+spoken+TAIL)*24)/24
        word_count = len(re.findall(r"\b[\w]+\b", speech))
        wpm = word_count*60/spoken
        assert 100 < wpm < 190, (i, wpm)
        chapters.append({'scene': i, 'title': title, 'start_seconds': round(elapsed,3), 'duration_seconds': duration})
        words = [json.loads(line) for line in (BUILD/f'scene-{i:02d}.jsonl').read_text().splitlines()]
        assert all(w['type'] == 'WordBoundary' for w in words)
        # Metadata-driven short subtitle cues; timing is not guessed from word count.
        for first in range(0, len(words), 8):
            group = words[first:first+8]
            start = elapsed+LEAD+group[0]['offset']/1e7
            end = elapsed+LEAD+(group[-1]['offset']+group[-1]['duration'])/1e7
            assert elapsed <= start < end <= elapsed+duration
            subtitle_id += 1
            captions.append(f'{subtitle_id}\n{stamp(start)} --> {stamp(end)}\n'+ ' '.join(w['text'] for w in group)+'\n')
        target = BUILD/f'scene-{i:02d}.mp4'
        print(f'Encoding scene {i}/9: {duration:.2f} seconds, {wpm:.0f} words/minute.', flush=True)
        subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-loop', '1',
            '-i', str(BUILD/f'scene-{i:02d}.png'), '-i', str(audio), '-t', str(duration),
            '-vf', 'fps=24,format=yuv420p', '-af', 'adelay=350,apad',
            '-c:v', 'libx264', '-preset', 'fast', '-tune', 'stillimage', '-crf', '22',
            '-c:a', 'aac', '-b:a', '128k', '-ar', '48000', '-ac', '2',
            '-movflags', '+faststart', str(target)], check=True)
        records.append({'scene': i, 'speech_seconds': spoken, 'words': word_count,
                        'speech_words_per_minute': round(wpm,1), 'scene_seconds': duration,
                        'audio_sha256': hashlib.sha256(audio.read_bytes()).hexdigest()})
        elapsed += duration
    concat = BUILD/'scenes.ffconcat'
    concat.write_text('ffconcat version 1.0\n'+''.join(f"file 'scene-{i:02d}.mp4'\n" for i in range(1,10)), encoding='ascii')
    assembled = BUILD/'assembled.mp4'
    subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-f','concat','-safe','1',
                    '-i',str(concat),'-c','copy','-movflags','+faststart',str(assembled)], check=True)
    synchronized = BUILD/'synchronized.wav'
    subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-i',str(assembled),
        '-vn','-af','aresample=async=1:first_pts=0,asetpts=N/SR/TB',
        '-c:a','pcm_s16le','-ar','48000',str(synchronized)],check=True)
    # Two-pass loudness normalization keeps speech comfortable without clipping.
    measured = subprocess.run(['ffmpeg','-hide_banner','-i',str(synchronized),'-vn',
        '-af','loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json','-f','null','NUL'],
        capture_output=True,text=True,check=True)
    loudness = json.JSONDecoder().raw_decode(measured.stderr[measured.stderr.rfind('{'):])[0]
    normalizer = ('loudnorm=I=-16:TP=-1.5:LRA=11:linear=true:'
        f"measured_I={loudness['input_i']}:measured_TP={loudness['input_tp']}:"
        f"measured_LRA={loudness['input_lra']}:measured_thresh={loudness['input_thresh']}:"
        f"offset={loudness['target_offset']}:print_format=json")
    video = OUT/'PrismGuard-32-narrated-demo.mp4'
    normalized = subprocess.run(['ffmpeg','-hide_banner','-y','-i',str(assembled),'-i',str(synchronized),
        '-map','0:v:0','-map','1:a:0','-c:v','copy','-af',normalizer,'-c:a','aac','-b:a','128k','-ar','48000',
        '-movflags','+faststart',str(video)],capture_output=True,text=True,check=True)
    normalized_measurement = re.search(r'\{\s*"input_i".*?\}',normalized.stderr,re.S)
    assert normalized_measurement
    normalized_loudness = json.loads(normalized_measurement.group())
    assert -17 <= float(normalized_loudness['output_i']) <= -15
    assert float(normalized_loudness['output_tp']) <= -1.4
    (OUT/'captions.srt').write_text('\n'.join(captions), encoding='utf-8', newline='\n')
    (OUT/'transcript.md').write_text('# PrismGuard-32 narrated demonstration\n\n'+
        '\n\n'.join(f'## {i}. {title}\n\n{speech}' for i,(title,speech) in enumerate(SCENES,1))+'\n',encoding='utf-8',newline='\n')
    final = probe(video)
    assert len([s for s in final['streams'] if s['codec_type']=='video']) == 1
    assert len([s for s in final['streams'] if s['codec_type']=='audio']) == 1
    assert abs(float(final['format']['duration'])-elapsed) < .5
    report = {'video': video.name, 'voice': VOICE, 'rate': RATE,
              'speech_service': 'Microsoft online neural speech via edge-tts',
              'client_version': edge_tts.__version__, 'scenes': records, 'chapters': chapters,
              'duration_seconds': float(final['format']['duration']), 'size_bytes': video.stat().st_size,
              'video_sha256': hashlib.sha256(video.read_bytes()).hexdigest(),
              'scene_lead_seconds': LEAD, 'minimum_scene_tail_seconds': TAIL,
              'loudness_normalization': normalized_loudness,
              'subtitle_source': 'speech-service word timestamps',
              'scope': 'Narrated caption-card walkthrough with actual captured demo excerpt; not a continuous screen recording.',
              'original_silent_video_preserved': True, 'core_crypto_sources_changed': False}
    (OUT/'video-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:report[k] for k in ['video','voice','duration_seconds','size_bytes','video_sha256']},indent=2),flush=True)

if __name__ == '__main__': main()
