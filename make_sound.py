"""Generates static/sounds/notification.mp3 - an original, soft two-note glass-bell chime (not a copy of any
commercial tone). Run once:  python make_sound.py   (needs numpy + ffmpeg)"""
import numpy as np, wave, subprocess, os
SR = 44100
def bell(freq, dur, amp=1.0):
    t = np.arange(int(SR * dur)) / SR
    # inharmonic partials give a glassy bell timbre; higher partials decay faster
    parts = [(1.0, 1.0, 5.0), (2.76, 0.45, 8.0), (5.4, 0.22, 12.0), (8.93, 0.10, 18.0), (0.5, 0.25, 4.0)]
    s = sum(a * np.exp(-d * t) * np.sin(2 * np.pi * freq * r * t) for r, a, d in parts)
    s *= np.minimum(1, t / 0.004)  # 4 ms attack: no click
    return amp * s
out = np.zeros(int(SR * 1.5))
for start, f, a in ((0.00, 1318.5, 0.85), (0.16, 1760.0, 1.0)):  # E6 -> A6, a bright rising "ding-ding"
    n = bell(f, 1.3, a); i = int(start * SR); out[i:i + len(n)] += n[:len(out) - i]
out *= np.minimum(1, (len(out) - np.arange(len(out))) / (0.08 * SR))  # fade tail
out = out / np.max(np.abs(out)) * 0.97  # normalised to near full scale = loud but not clipped
w = wave.open("tmp.wav", "wb"); w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR)
w.writeframes((out * 32767).astype(np.int16).tobytes()); w.close()
subprocess.check_call(["ffmpeg", "-y", "-loglevel", "error", "-i", "tmp.wav", "-codec:a", "libmp3lame", "-b:a", "128k",
                       os.path.join("static", "sounds", "notification.mp3")])
os.remove("tmp.wav")
