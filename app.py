# 마음 사이 | Python 3.11+ | streamlit run app.py
# 두 파일 배포: app.py + requirements.txt
# API 키 불필요. 가족 데이터와 DB 비밀번호는 GitHub에 올리지 마세요.
# 실행/배포/개인정보 안내는 앱 하단의 설치 · 운영 안내에서 확인하세요.
import hashlib
import hmac
import re
import secrets
import json


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def valid_password(password, salt, expected):
    return hmac.compare_digest(password_hash(password, salt), expected)


def redact(text):
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[연락처 삭제]", text)
    text = re.sub(r"https?://\S+", "[링크 삭제]", text)
    text = re.sub(r"\b\d{6}[- ]?[1-4]\d{6}\b", "[민감정보 삭제]", text)
    text = re.sub(r"(?<!\d)0\d{1,2}[- .]?\d{3,4}[- .]?\d{4}(?!\d)", "[연락처 삭제]", text)
    return text


def local_review(task, data):
    # No API calls: deterministic keyword matching, not generative AI.
    if task == 'sanitize':
        text = redact(data['opinion'])
        text = re.sub(r'(엄마|아빠|어머니|아버지|누나|언니|오빠|형|동생|아들|딸|남편|아내|할머니|할아버지)', '[가족]', text)
        text = re.sub(r'(?<![가-힣])[가-힣]{2,4}(?=씨|님)', '[이름]', text)
        text = re.sub(r'\d{1,4}년|\d{1,2}월|\d{1,2}일|\d{1,2}시|\d{1,3}살', '[시점·나이]', text)
        return {'text': text}
    notes = data.get('opinions', [])
    rules = [
        ('대화·경청', ['말', '대화', '듣', '무시'], '서로의 말을 끝까지 듣기'),
        ('가사·역할', ['청소', '설거지', '집안일', '분담'], '생활 역할을 함께 정하기'),
        ('휴식·경계', ['쉬', '피곤', '혼자', '사생활'], '휴식과 개인 공간 존중하기'),
        ('경제·소비', ['돈', '용돈', '지출', '경제'], '지출 기준을 함께 정하기'),
        ('기대·압박', ['공부', '성적', '기대', '비교', '잔소리'], '기대를 강요하지 않고 요청으로 말하기')]
    counts = [(label, sum(any(k in n for k in keys) for n in notes), need) for label, keys, need in rules]
    counts.sort(key=lambda x: -x[1])
    matched = [(label, n, need) for label, n, need in counts if n]
    combined = ' '.join(notes)
    emotions = [label+' 관련 표현' for label, keys in [('속상함', ['속상', '서운', '슬프']), ('분노', ['화나', '짜증', '억울']), ('불안', ['불안', '걱정', '무섭']), ('지침', ['피곤', '지쳐', '힘들'])] if any(k in combined for k in keys)]
    danger = any(k in combined for k in ['때리', '폭력', '죽', '자해', '학대', '위협'])
    return {
        'emotions': emotions or ['감정 키워드를 찾지 못했습니다. 직접 감정을 확인해 주세요.'],
        'common': [need+' · 해당 키워드가 있는 의견 '+str(n)+'건 (같은 사람의 중복 작성 가능)' for _, n, need in matched] or ['공통 필요를 자동으로 확인하지 못했습니다.'],
        'causes': ['키워드로 갈등의 실제 원인을 판정할 수 없습니다. 각자의 기대와 상황을 안전하게 확인해 주세요.'],
        'solutions': [
            {'title': '안전한 대화 약속', 'action': '모두가 안전하다고 느끼고 자발적으로 동의할 때만 10분 대화하세요. 비난·작성자 추측은 멈추고 누구나 중단할 수 있게 합니다.', 'check': '대화 전 참여와 중단 규칙에 동의했는지 확인'},
            {'title': '작은 실천 한 가지', 'action': ('검토할 주제: '+matched[0][2]+'. ' if matched else '')+'원하는 행동 한 가지를 함께 고르고 일주일만 시험하세요.', 'check': '실천 내용과 점검 날짜를 함께 정하기'},
            {'title': '부담 없는 재점검', 'action': '일주일 뒤 도움이 된 점과 바꾸고 싶은 점을 각각 하나씩 나눕니다. 합의가 어려우면 중립적인 전문 상담을 고려하세요.', 'check': '누구의 잘못인지가 아니라 실천의 효과만 확인'}],
        'dialogue': ['참여 의사를 묻고 불편하면 중단하기', '나는 …할 때 …하게 느껴요. …해 주면 좋겠어요.', '상대 말의 의미를 다시 확인한 뒤 실천 하나 합의하기'],
        'safety': ('위험 관련 단어가 감지됐습니다. 실제 위험을 판정한 것은 아닙니다. 폭력·위협이 있다면 공동 대화보다 안전한 장소와 전문 지원이 우선이며 긴급 위험은 112 또는 119에 연락하세요.' if danger else '')}


import os
import sqlite3
import secrets
from contextlib import contextmanager

class Store:
    def __init__(self, url=''):
        self.url=url
        with self.connection() as c:
            c.execute("CREATE TABLE IF NOT EXISTS rooms (id TEXT PRIMARY KEY, salt TEXT NOT NULL, digest TEXT NOT NULL, admin_salt TEXT NOT NULL, admin_digest TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, content TEXT NOT NULL, delete_salt TEXT NOT NULL, delete_digest TEXT NOT NULL)")
    @contextmanager
    def connection(self):
        if self.url:
            import psycopg
            conn=psycopg.connect(self.url,connect_timeout=10)
        else:
            conn=sqlite3.connect('family_local.db',timeout=10)
            conn.execute('PRAGMA foreign_keys=ON')
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    def sql(self, s):
        return s.replace('?', '%s') if self.url else s
    def create(self, password):
        room=secrets.token_hex(8); salt=secrets.token_hex(16)
        admin=secrets.token_urlsafe(24); admin_salt=secrets.token_hex(16)
        with self.connection() as c:
            c.execute(self.sql('INSERT INTO rooms VALUES (?,?,?,?,?)'),(room,salt,password_hash(password,salt),admin_salt,password_hash(admin,admin_salt)))
        return room,admin
    def login(self, room, password):
        with self.connection() as c:
            row=c.execute(self.sql('SELECT salt,digest FROM rooms WHERE id=?'),(room,)).fetchone()
        return bool(row and valid_password(password,*row))
    def notes(self, room):
        with self.connection() as c:
            return c.execute(self.sql('SELECT content FROM notes WHERE room_id=?'),(room,)).fetchall()
    def add(self, room, text):
        ident=secrets.token_hex(16); token=secrets.token_urlsafe(24); salt=secrets.token_hex(16)
        with self.connection() as c:
            c.execute(self.sql('INSERT INTO notes VALUES (?,?,?,?,?)'),(ident,room,text,salt,password_hash(token,salt)))
        return ident+'.'+token
    def remove(self, room, receipt):
        ident,token=receipt.strip().split('.',1)
        with self.connection() as c:
            row=c.execute(self.sql('SELECT delete_salt,delete_digest FROM notes WHERE id=? AND room_id=?'),(ident,room)).fetchone()
            if not row or not valid_password(token,*row): return False
            c.execute(self.sql('DELETE FROM notes WHERE id=? AND room_id=?'),(ident,room))
        return True
    def destroy(self, room, token):
        with self.connection() as c:
            row=c.execute(self.sql('SELECT admin_salt,admin_digest FROM rooms WHERE id=?'),(room,)).fetchone()
            if not row or not valid_password(token,*row): return False
            c.execute(self.sql('DELETE FROM notes WHERE room_id=?'),(room,))
            c.execute(self.sql('DELETE FROM rooms WHERE id=?'),(room,))
        return True


import streamlit as st
import time

st.set_page_config(page_title='마음 사이',page_icon='🌿',layout='centered',initial_sidebar_state='collapsed')
st.markdown('''<style>
.block-container{max-width:620px;padding-top:4.5rem;padding-bottom:1rem}
h1{font-size:1.45rem!important;line-height:1.5!important;padding-top:.25rem!important;padding-bottom:.35rem!important;margin:0!important;overflow:visible!important}p{font-size:.88rem;overflow-wrap:anywhere}
div[data-testid="stVerticalBlock"]{gap:.38rem}
div.stButton>button,div.stFormSubmitButton>button{min-height:40px;border-radius:10px}
@media(max-width:640px){.block-container{padding-left:.8rem;padding-right:.8rem}}
</style>''',unsafe_allow_html=True)

def cfg(k, default=''):
    try: return st.secrets.get(k,default)
    except FileNotFoundError: return default

def invalidate():
    st.session_state.pop('result',None)
    st.session_state.pop('fingerprint',None)

def call_ai(task,data):
    return local_review(task,data)

with st.expander('📖 처음 사용하시나요? · 사용 방법', expanded='room' not in st.session_state):
    st.markdown("""**1. 공간 만들기** · 아래 ‘처음이라면 · 가족 공간 만들기’에서 12자 이상 비밀번호를 정하고 공간을 만드세요.

**2. 가족 초대** · 공간 코드와 비밀번호를 보관하고, 앱 주소와 함께 가족에게 전달하세요. 전체 삭제 키는 관리자만 보관하세요.

**3. 입장하기** · 공간 코드와 공유 비밀번호를 입력하고 ‘입장’을 누르세요.

**4. 마음 남기기** · 입장 후 의견 작성 → 개인정보 점검 확인 → 개인정보 점검 미리보기 → 신원 단서 확인 → 등록 순서로 진행하세요. 삭제 코드를 보관하세요.

**5. 함께 해결하기** · 가족 마음을 읽고 ‘자동 정리 · 해결책 3가지’에서 분석을 실행하세요. 필요한 항목만 펼쳐 볼 수 있습니다.""")
    st.caption('이름·연락처·특정 사건은 적지 마세요. 문맥으로 신원이 추측될 수 있고, 외부 AI 전송 없이 처리하지만 이름·문맥을 완벽히 가리지는 못합니다. 입장 시 잠시 기다리라는 안내가 나오면 5초 뒤 다시 시도하세요.')
st.title('🌿 마음 사이')
st.caption('익명으로 전하는 마음 · 무료 규칙 기반 정리 · 외부 AI 전송 없음')
try: db=Store(cfg('DATABASE_URL'))
except Exception:
    st.error('DB 연결 실패. DATABASE_URL을 확인하세요.'); st.stop()

if 'room' not in st.session_state:
    st.caption('이름을 받지 않습니다. 내용으로 신원이 추측될 수 있습니다. 무료 규칙 기반 기능이며 생성형 AI가 아닙니다.')
    with st.form('enter'):
        room=st.text_input('가족 공간 코드',max_chars=32).strip()
        pw=st.text_input('공유 비밀번호',type='password',max_chars=128)
        submitted=st.form_submit_button('입장',use_container_width=True)
    if submitted:
        now=time.time()
        if now<st.session_state.get('login_next',0): st.warning('잠시 후 다시 시도하세요.')
        else:
            st.session_state.login_next=now+5
            try: ok=db.login(room,pw)
            except Exception: ok=False
            if ok:
                st.session_state.clear(); st.session_state.room=room; st.rerun()
            else: st.error('코드 또는 비밀번호를 확인하세요.')
    with st.expander('처음이라면 · 가족 공간 만들기'):
        with st.form('create'):
            pw=st.text_input('새 공유 비밀번호 · 12자 이상',type='password',max_chars=128)
            agree=st.checkbox('가족에게 자동 점검의 한계와 신원 추측 위험을 안내하겠습니다.')
            created=st.form_submit_button('만들기')
        if created:
            if len(pw)<12 or not agree: st.warning('12자 이상 비밀번호와 동의가 필요합니다.')
            else:
                try: st.session_state.created=db.create(pw)
                except Exception: st.error('생성에 실패했습니다.')
        if st.session_state.get('created'):
            r,t=st.session_state.created
            st.code('공간 코드: '+r+'\n전체 삭제 키: '+t,language=None)
            st.caption('두 값을 별도 보관한 뒤 위에서 입장하세요. 삭제 키는 복구할 수 없습니다.')
else:
    room=st.session_state.room
    st.caption('작성자 추측·추궁 금지 · 신원 단서는 직접 확인 · 위험할 때는 화해보다 안전')
    with st.expander('✍️ 마음 남기기',expanded=False):
        with st.form('write',clear_on_submit=True):
            raw=st.text_area('감정과 바라는 점 · 이름/관계/사건 단서 제외',height=68,max_chars=1000,placeholder='내 이야기를 끝까지 들어 주면 좋겠어요.')
            agree=st.checkbox('자동 점검만으로 모든 개인정보가 제거되지 않음을 확인했습니다.')
            sent=st.form_submit_button('개인정보 점검 미리보기',use_container_width=True)
        if sent:
            st.session_state.pop('preview',None)
            if not raw.strip() or not agree: st.warning('내용과 전송 동의가 필요합니다.')
            else:
                a=call_ai('sanitize',{'opinion':redact(raw.strip())})
                if a: st.session_state.preview=a['text']
        if st.session_state.get('preview'):
            st.write(st.session_state.preview)
            checked=st.checkbox('의미가 맞고 신원 단서가 없는지 확인했습니다.')
            if st.button('이 문장 등록',disabled=not checked):
                try:
                    receipt=db.add(room,st.session_state.preview)
                    st.session_state.receipt=receipt
                    st.session_state.pop('preview',None); invalidate()
                    st.success('등록했습니다. 아래 삭제 코드를 보관하세요.')
                except Exception: st.error('저장 실패. 다시 시도하세요.')
            if st.button('미리보기 취소'):
                st.session_state.pop('preview',None); st.rerun()
        if st.session_state.get('receipt'):
            st.caption('내 의견 삭제 코드 · 나가기 전에 보관')
            st.code(st.session_state.receipt,language=None)
    try: notes=[x[0] for x in db.notes(room)]
    except Exception: st.error('의견을 불러오지 못했습니다.'); st.stop()
    fingerprint=hashlib.sha256(json.dumps(sorted(notes),ensure_ascii=False).encode()).hexdigest()
    if st.session_state.get('fingerprint')!=fingerprint: invalidate()
    with st.expander('💬 가족 마음 모아보기'):
        st.caption('순서는 무작위입니다. 표시 시각·이름은 없습니다. 문맥으로 추측될 위험은 남습니다.')
        st.button('순서 다시 섞기')
        secrets.SystemRandom().shuffle(notes)
        if not notes: st.info('아직 의견이 없습니다.')
        for text in notes:
            with st.container(border=True): st.write(text)
    with st.expander('🌱 자동 정리 · 해결책 3가지'):
        st.caption('무료 규칙 기반 키워드 정리입니다. 생성형 AI가 아니며 인물·원인·의견의 진위를 판정하지 않습니다.')
        agree=st.checkbox('규칙 기반 정리와 일반적인 대화 안내의 한계를 확인했습니다.')
        if st.button('분석하기',disabled=not agree or not notes,use_container_width=True):
            shuffled=list(notes); secrets.SystemRandom().shuffle(shuffled)
            a=call_ai('analysis',{'opinions':shuffled})
            if a:
                st.session_state.result=a; st.session_state.fingerprint=fingerprint
        a=st.session_state.get('result')
        if a:
            if a['safety']: st.warning(a['safety'])
            for title,k in [('감정','emotions'),('공통 필요','common'),('갈등 원인 · 가설','causes')]:
                st.markdown('**'+title+'**'); st.write(' / '.join(a[k]))
            for i,s in enumerate(a['solutions'],1):
                st.markdown('**'+str(i)+'. '+s['title']+'**')
                st.write(s['action']); st.caption('실천 확인: '+s['check'])
            st.markdown('**함께 대화하기**')
            for i,text in enumerate(a['dialogue'],1): st.write(str(i)+'. '+text)
        elif not notes: st.caption('먼저 의견을 등록해 주세요.')
    with st.expander('⚙️ 공간 정보 · 삭제 · 개인정보 안내'):
        st.code('가족 공간 코드: '+room,language=None)
        st.caption('원문은 DB에 저장하지 않습니다. 외부 AI에는 전송하지 않습니다. 완전 익명은 보장하지 않습니다. 자동 마스킹에서 놓친 개인정보는 DB에 남을 수 있습니다. 운영자와 DB 관리자는 익명화된 내용을 볼 수 있습니다. 자동 삭제는 없으며 가족 대화 종료 후 삭제를 권장합니다.')
        with st.form('delete_one'):
            receipt=st.text_input('내 의견 삭제 코드',type='password')
            delete=st.form_submit_button('내 의견 삭제')
        if delete:
            try: ok=db.remove(room,receipt)
            except Exception: ok=False
            if ok:
                invalidate(); st.session_state.pop('receipt',None); st.rerun()
            else: st.error('삭제 코드를 확인하세요.')
        with st.form('delete_all'):
            token=st.text_input('관리용 전체 삭제 키',type='password')
            confirm=st.checkbox('공간과 의견을 복구할 수 없게 삭제합니다.')
            delete=st.form_submit_button('공간 전체 삭제',disabled=not confirm)
        if delete:
            try: ok=db.destroy(room,token)
            except Exception: ok=False
            if ok: st.session_state.clear(); st.rerun()
            else: st.error('관리 키를 확인하세요.')
        st.caption('삭제해도 다른 기기의 화면·캡처·공급자 백업은 즉시 지워지지 않습니다. 공유 비밀번호 유출 시 타인이 읽고 쓸 수 있습니다.')
    if st.button('나가기 · 화면 기록 지우기',use_container_width=True):
        st.session_state.clear(); st.rerun()

with st.expander('설치 · 운영 안내'):
    st.caption('무료 규칙 기반 버전: API 키·AI 결제·외부 AI 전송이 없습니다. 생성형 AI 기능은 포함하지 않습니다.')
    st.caption('GitHub의 app.py와 requirements.txt를 교체하세요. Streamlit 실행 파일은 app.py입니다. 기존 OPENAI_API_KEY와 AI_MODEL 설정은 필요 없으므로 삭제해도 됩니다. DATABASE_URL 설정은 유지하세요.')
    st.caption('별도 설정 없이 SQLite로 실행할 수 있으나 재배포 시 데이터가 사라질 수 있습니다. 지속 보관은 별도 PostgreSQL 연결이 필요하며 호스팅·DB의 무료 한도는 공급자 정책에 따릅니다. DB 설정과 API 키를 GitHub에 올리지 마세요.')
    st.caption('공개 서비스용 전역 사용량 제한·비밀번호 변경·자동 삭제는 미구현입니다. 소규모 시범용으로 사용하고 대화가 끝나면 공간을 삭제하세요.')
    if not cfg('DATABASE_URL'): st.warning('로컬 저장 모드: 재배포 시 데이터가 사라질 수 있습니다.')
