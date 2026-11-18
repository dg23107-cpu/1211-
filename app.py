"""마음 여백 — Streamlit 가족 익명 소통 실험.
배포: requirements.txt와 함께 GitHub 업로드 → Streamlit Community Cloud.
Secrets 필수:
APP_SECRET = "충분히 길고 무작위인 32자 이상의 비밀 문자열"
외부 AI API 및 모델 다운로드 없음: 규칙 기반 대화 도우미.
선택: DB_PATH = "family.db"  # 영속 디스크 경로 권장
주의: Community Cloud 로컬 DB는 재시작/재배포 시 유실될 수 있음.
실제 가족의 장기 기록 보관용으로 사용하기 전 영속 저장소 필요.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import streamlit as st
from cryptography.fernet import Fernet

st.set_page_config(page_title='마음 여백', page_icon='🌿', layout='wide')
st.markdown("""<style>
.stApp{background:#f5f4ef;color:#253c36}
.block-container{max-width:1540px;padding:0.65rem 1.6rem 0.5rem}
h1{font-size:1.65rem!important;letter-spacing:-.06em;margin:0!important;padding:0!important}
h3{font-size:1.04rem!important;padding:.1rem 0 .3rem!important}
p,li,label{font-size:14px!important;line-height:1.45;overflow-wrap:anywhere}
[data-testid="stCaptionContainer"] p{font-size:12px!important;color:#52675f}
[data-testid="stVerticalBlock"]{gap:.5rem}
[data-testid="stHorizontalBlock"]{gap:1rem}
[data-testid="stVerticalBlockBorderWrapper"]{background:#fff;border-radius:17px}
.stButton button,.stFormSubmitButton button{border-radius:10px;min-height:36px;font-size:13px}
textarea,input{font-size:14px!important}
[data-testid="stAlert"]{padding:.5rem .7rem}
[data-testid="stAlert"] p{font-size:12px!important}
hr{margin:.3rem 0!important}
@media(max-width:900px){.block-container{padding:1rem}.stHorizontalBlock{flex-wrap:wrap}}
/* No overflow:hidden: small viewports retain access instead of clipping controls. */
</style>""", unsafe_allow_html=True)

def setting(k, default=''):
    try:
        return str(st.secrets.get(k, os.environ.get(k, default)))
    except Exception:
        return os.environ.get(k, default)

MASTER=setting('APP_SECRET')
st.title('🌿 마음 여백')
st.caption('말하기 어려운 마음에도, 잠시 놓아둘 여백을 · 외부 AI 없는 가족 대화 공간')
if len(MASTER)<32:
    st.warning('먼저 배포 설정의 Secrets에 APP_SECRET을 32자 이상으로 설정하세요. 키를 바꾸면 기존 암호화 기록을 읽을 수 없습니다.')
    st.code('APP_SECRET = "여기에_충분히_길고_무작위인_비밀문자열을_설정하세요"', language='toml')
    st.stop()
FERNET=Fernet(base64.urlsafe_b64encode(hashlib.sha256(('encryption:'+MASTER).encode()).digest()))
DB=setting('DB_PATH','family.db')

def seal(text): return FERNET.encrypt(text.encode()).decode()
def unseal(text): return FERNET.decrypt(text.encode()).decode()
def digest(text): return hmac.new(MASTER.encode(),text.encode(),hashlib.sha256).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat()

@contextmanager
def db():
    con=sqlite3.connect(DB, timeout=15)
    try:
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('PRAGMA secure_delete=ON')
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

with db() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS rooms(id TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL, created TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS opinions(id TEXT PRIMARY KEY, room TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, body TEXT NOT NULL, deletion_hash TEXT NOT NULL, created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS plans(room TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE, body TEXT NOT NULL, updated TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS attempts(room TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE, last REAL NOT NULL);
    """)

def verifier(password,salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),240000).hex()

def room_id(code): return digest('room:'+code.strip().upper())

def logout():
    for key in list(st.session_state): del st.session_state[key]
    st.rerun()

if 'room' not in st.session_state:
    st.info('이름·가족관계·작성자 계정은 수집하지 않습니다. 가족끼리만 공유하는 방 코드와 비밀번호로 입장하세요.')
    login,create=st.tabs(['가족방 입장','새 가족방 만들기'])
    with login:
        with st.form('login'):
            code=st.text_input('방 코드',max_chars=32)
            password=st.text_input('방 비밀번호',type='password',max_chars=128)
            submitted=st.form_submit_button('입장하기',use_container_width=True)
        if submitted:
            import time
            rid=room_id(code)
            with db() as c:
                row=c.execute('SELECT salt,verifier,failures,locked_until FROM rooms WHERE id=?',(rid,)).fetchone()
                valid=False
                if row and row[3]<=time.time():
                    valid=hmac.compare_digest(verifier(password,row[0]),row[1])
                    if valid:
                        c.execute('UPDATE rooms SET failures=0,locked_until=0 WHERE id=?',(rid,))
                    else:
                        n=row[2]+1
                        c.execute('UPDATE rooms SET failures=?,locked_until=? WHERE id=?',(n,time.time()+300 if n>=5 else 0,rid))
            if valid:
                st.session_state.room=rid
                st.rerun()
            else: st.error('입장 정보를 확인하세요. 반복 실패한 방은 5분 후 다시 시도할 수 있습니다.')
    with create:
        with st.form('create'):
            newpw=st.text_input('새 비밀번호 (12자 이상)',type='password',max_chars=128)
            agree=st.checkbox('가족 모두에게 이용 목적과 익명성의 한계를 설명하겠습니다.')
            made=st.form_submit_button('비밀방 생성',use_container_width=True)
        if made:
            if len(newpw)<12 or not agree: st.error('12자 이상 비밀번호와 동의가 필요합니다.')
            else:
                newcode=secrets.token_hex(6).upper()
                salt=secrets.token_hex(16)
                with db() as c: c.execute('INSERT INTO rooms(id,salt,verifier,created) VALUES(?,?,?,?)',(room_id(newcode),salt,verifier(newpw,salt),now()))
                st.success('방이 만들어졌습니다. 코드는 이 화면에서만 표시됩니다. 안전한 곳에 기록한 뒤 입장하세요.')
                st.code(newcode)
    with st.expander('배포 전 반드시 알아둘 점'):
        st.write('공유 비밀번호를 아는 사람은 모두 같은 가족 구성원 권한입니다. 이름을 저장하지 않아도 문체·사건으로 작성자를 추측할 수 있습니다. 호스팅 사업자는 접속 정보를 처리할 수 있고, 앱 운영자는 서버 및 비밀키에 접근할 수 있습니다. 완전 익명 서비스가 아닙니다.')
        st.write('현재 저장소는 암호화된 SQLite 시제품입니다. Streamlit Community Cloud에서 재시작·재배포하면 데이터가 사라질 수 있습니다. 장기 운영 전 외부 영속 DB로 바꾸세요. 암호화만으로 운영자 접근을 막을 수는 없습니다.')
    st.stop()

# 규칙 기반 점검은 모든 개인정보를 찾아내는 탐지기가 아님.
RULES=[
 (r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}','[이메일]'),
 (r'(?<!\d)\d{6}\s*[-–]?\s*[1-8]\d{6}(?!\d)','[식별번호]'),
 (r'(?<!\d)(?:\+82[- .]?)?0?1[016789][- .]?\d{3,4}[- .]?\d{4}(?!\d)','[연락처]'),
 (r'https?://\S+|www\.\S+','[링크]'),
 (r'(?<!\d)\d{2,6}[- ]\d{2,6}[- ]\d{2,8}(?!\d)','[번호]'),
 (r'(?<!\d)\d{3,}(?!\d)','[숫자]'),
 (r'[가-힣]{2,}(?:로|길)\s*\d+(?:-\d+)?','[주소]'),
 (r'[가-힣]{2,}(?:초등학교|중학교|고등학교|대학교)','[학교]'),
 (r'(?:내\s*이름은?|이름[:：])\s*[가-힣]{2,4}','[이름 표현]'),
 (r'(?:엄마|아빠|어머니|아버지|누나|언니|오빠|형|동생|할머니|할아버지|딸|아들)','가족'),
 (r'(?<![가-힣])(?:어제|오늘|그저께|내일|월요일|화요일|수요일|목요일|금요일|토요일|일요일)(?![가-힣])','최근'),
]
def redact(text,extra=''):
    out=text
    for word in sorted([x.strip() for x in extra.split(',') if x.strip()],key=len,reverse=True):
        out=out.replace(word,'[가림]')
    for pattern,replacement in RULES: out=re.sub(pattern,replacement,out,flags=re.I)
    return out.strip()

def get_opinions():
    with db() as c: rows=c.execute('SELECT id,body FROM opinions WHERE room=?',(RID,)).fetchall()
    return [(i,unseal(b)) for i,b in rows]

# 규칙 사전: 임상 진단이나 통계적 감정 추정 모델이 아님.
EMOTIONS={
    '속상함·슬픔':['속상','슬프','서운','울고','눈물','외롭'],
    '답답함·화':['짜증','화가','화나','답답','억울','불공평'],
    '걱정·긴장':['걱정','불안','긴장','무서','두려'],
    '지침·부담':['피곤','지쳐','지친','힘들','부담','스트레스'],
    '고마움·기쁨':['고마','감사','행복','기쁘','좋았'],
}
TOPICS={
    '경청과 존중':{'words':['안 들어','안들어','말을 끊','무시','잔소리','비난','소리','존중','대화'],
        'cause':'말하는 순서나 피드백 방식이 맞지 않을 가능성',
        'title':'2분씩 말하고 한 문장으로 되짚기',
        'action':'원하는 사람만 참여해 2분씩 말합니다. 듣는 사람은 반박 전에 “내가 들은 뜻은 이거야. 맞을까?”라고 확인합니다.',
        'check':'일주일 뒤 “말을 끝까지 할 기회가 있었나?”를 함께 돌아봅니다.'},
    '공정한 역할 분담':{'words':['집안일','설거지','청소','빨래','나만','분담','불공평','심부름'],
        'cause':'일의 양뿐 아니라 기억하고 계획하는 부담이 다르게 보일 가능성',
        'title':'보이지 않는 일까지 함께 나누기',
        'action':'가족이 하는 일과 챙기는 일을 적고, 각자 가능한 일 하나를 자발적으로 선택합니다. 사람별 순위는 매기지 않습니다.',
        'check':'일주일 뒤 특정 사람의 부담이 늘지 않았는지 확인합니다.'},
    '자율성과 합의된 경계':{'words':['휴대폰','휴대전화','핸드폰','게임','공부','성적','간섭','비교','허락','자유'],
        'cause':'스스로 선택하고 싶은 마음과 함께 지키고 싶은 기준이 다를 가능성',
        'title':'일방적인 금지 대신 시험 규칙 합의하기',
        'action':'각자 필요한 자유와 우려를 한 가지씩 말하고, 모두가 동의한 규칙 하나만 7일 동안 시험합니다.',
        'check':'규칙이 실제로 도움이 됐는지와 바꿔야 할 점을 함께 확인합니다.'},
    '휴식과 개인 공간':{'words':['피곤','쉬고','휴식','혼자','잠','지쳐','지친','바빠','시간이 없','스트레스'],
        'cause':'쉬는 시간이나 혼자 있을 필요가 충분히 전달되지 않았을 가능성',
        'title':'방해받지 않는 짧은 휴식 정하기',
        'action':'각자 원한다면 하루 15분의 휴식 시간을 정하고, 급하지 않은 부탁은 그 시간이 지난 뒤에 전합니다.',
        'check':'휴식이 실제로 보장됐는지, 다른 사람에게 부담이 전가되지 않았는지 확인합니다.'},
    '연결감과 함께하는 시간':{'words':['외롭','함께','같이','관심','혼자인','가족 시간'],
        'cause':'함께 보내고 싶은 시간의 양이나 방식이 다를 가능성',
        'title':'부담 없는 10분 함께 보내기',
        'action':'참여 여부를 자유롭게 정하고, 하루 10분 산책이나 간식처럼 부담 없는 활동을 하나 고릅니다.',
        'check':'즐거웠는지, 참여 압박은 없었는지 일주일 뒤 확인합니다.'},
}
DEFAULT_SOLUTIONS=[
    {'title':'감정·필요·요청을 나눠 말하기','action':'“나는 지금 ___하게 느껴. 내게 ___가 필요해서, ___해 줄 수 있을까?” 틀로 한 문장만 말합니다.','check':'서로 어떤 요청을 했는지 같은 뜻으로 이해했는지 확인합니다.'},
    {'title':'대화 중단 신호 정하기','action':'목소리가 높아지면 누구나 중단을 요청하고, 안전할 때 다시 이야기할 시점을 합의합니다.','check':'쉬고 싶다는 요청이 존중됐는지 확인합니다.'},
    {'title':'작은 약속 하나만 시험하기','action':'모두가 자발적으로 동의한 행동 하나를 정해 7일간 시험하고, 도움이 없으면 수정합니다.','check':'누군가에게 불리하거나 부담스러운 약속은 아니었는지 확인합니다.'},
]
DANGER=['죽고 싶','죽고싶','자살','자해','죽일','때려','때리','폭행','학대','칼로','협박','맞았','맞고','맞을','성폭력','성추행']
SAFETY='이 표현은 긴급한 위험뿐 아니라 비유나 과거 경험일 수도 있어 챗봇이 판단할 수 없습니다. 지금 안전한 곳인가요? 실제 위험이 있으면 가족 대화나 화해보다 안전한 장소와 믿을 만한 어른·전문기관의 도움을 우선하세요. 즉각적 위험은 112·119, 청소년 상담은 1388, 자살예방상담은 109입니다. 챗봇은 구조 요청을 대신하지 못합니다.'

def danger(text):
    return any(word in text for word in DANGER)

def find_topics(texts):
    # 한 의견에서 같은 단어가 반복돼도 주제별 최대 1회만 셈.
    scored=[]
    for name,item in TOPICS.items():
        n=sum(any(word in text for word in item['words']) for text in texts)
        if n: scored.append((name,n))
    return sorted(scored,key=lambda x:(-x[1],x[0]))

def analyze_local(texts):
    if any(danger(t) for t in texts):
        return {'emotions':['안전 관련 단서가 있어 일반적인 감정 추정을 생략합니다.'],
            'common_needs':['누구에게나 안전과 대화 중단의 권리가 우선합니다.'],
            'differences':['공동 대화나 화해가 안전하지 않을 수 있습니다.'],
            'causes':['규칙 기반 도우미는 사건의 사실관계나 원인을 판정할 수 없습니다.'],
            'solutions':[
                {'title':'즉각적인 안전 확보','action':'실제 위험이 있으면 대화와 앱 사용을 멈추고 안전한 곳으로 이동하세요.','check':'지금 안전한지 먼저 확인하세요.'},
                {'title':'도움을 줄 사람에게 연결','action':'안전하게 연락할 수 있는 믿을 만한 어른이나 전문기관에 도움을 요청하세요.','check':'안전하게 연락할 방법이 있는지 확인하세요.'},
                {'title':'긴급 위험에는 긴급기관 이용','action':'즉각적인 위험은 112·119에 연락하세요. 청소년 상담 1388, 자살예방상담 109도 이용할 수 있습니다.','check':'위험이 계속되면 앱의 답을 기다리지 마세요.'}],
            'conversation':['원치 않는 공동 대화나 공개를 강요하지 마세요.'], 'safety':SAFETY}
    emotions=[name+' 관련 표현이 있습니다. 실제 감정은 직접 확인해야 합니다.' for name,words in EMOTIONS.items() if any(any(w in t for w in words) for t in texts)]
    themes=find_topics(texts)
    solutions=[{k:TOPICS[name][k] for k in ['title','action','check']} for name,_ in themes[:3]]
    for item in DEFAULT_SOLUTIONS:
        if len(solutions)>=3: break
        solutions.append(dict(item))
    return {'emotions':emotions or ['사전에 있는 감정 표현을 찾지 못했습니다. 감정이 없다는 뜻은 아닙니다.'],
        'common_needs':[name+'에 관한 표현이 있어 확인할 주제로 제안합니다.' for name,_ in themes] or ['공통된 필요를 판단할 단서가 부족합니다. 각자 필요한 것을 직접 확인하세요.'],
        'differences':['키워드가 비슷해도 원하는 해결책은 다를 수 있습니다. 적게 등장한 요구도 직접 확인하세요.','한 사람이 여러 의견을 쓸 수 있으므로 빈도를 인원수나 찬성률로 해석하지 않습니다.'],
        'causes':[TOPICS[name]['cause'] for name,_ in themes] or ['감정 표현 방식이나 기대의 차이가 있는지 질문해 볼 수 있지만 현재 단서로 원인을 판단할 수 없습니다.'],
        'solutions':solutions,
        'conversation':['“나는 ___하게 느껴. 내게 필요한 것은 ___야.”','“내가 들은 뜻은 ___인데, 맞을까?”','“모두에게 부담이 적은 행동 하나를 7일만 시험해 볼까?”'],
        'safety':'규칙 기반 참고 결과입니다. 부정문·반어·은유·맥락을 잘못 읽을 수 있으며, 공통 감정·원인·작성자를 판정하지 않습니다.'}

def chat_reply(text,history):
    if danger(text): return SAFETY
    # 직전 대화가 위험 단서였다면 짧은 확인 답변도 일반 조언으로 전환하지 않음.
    recent=[m['content'] for m in history[-4:] if m['role']=='user']
    if any(danger(t) for t in recent):
        return '앞선 안전 이야기를 먼저 확인하고 싶어요. 이 챗봇은 안전 여부를 판단할 수 없습니다. '+SAFETY
    if any(w in text for w in ['안녕','반가워']):
        return '안녕하세요. 가족 대화 도우미 마음이예요. 정해진 규칙 안에서 감정을 정리하고 부탁하는 문장을 만드는 것을 도와드려요. 지금은 공감이 필요한가요, 요청 문장을 만들고 싶은가요?'
    if any(w in text for w in ['고마워','감사해']):
        return '이야기해 줘서 고마워요. 지금 제안 중 해볼 만한 것 하나만 골라도 괜찮아요. 대화를 마치면 공유 기기에서는 대화 지우기를 눌러주세요.'
    if any(w in text for w in ['누가 썼','작성자','정체','누구 편','누가 잘못']):
        return '작성자를 추측하거나 잘잘못을 판정하지 않아요. 대신 어떤 감정과 필요가 전달됐는지 함께 살펴볼 수 있어요.'
    combined=text
    if any(w in text for w in ['어떻게','방법','문장','부탁','해결','응','네','맞아','공감']):
        previous=next((m['content'] for m in reversed(history[-6:]) if m['role']=='user'), '')
        combined=previous+' '+text
    data=analyze_local([combined])
    if any(w in text for w in ['문장','부탁','말하면','말할까','바꿔']):
        return '상대의 의도를 단정하지 않고 이렇게 시작해 보세요. “나는 지금 ___하게 느껴. 내게 필요한 건 ___야. 가능하다면 ___해 줄 수 있을까?” 구체적인 요청은 하나만 정하고, 상대가 거절하거나 다른 방법을 제안할 여지도 남겨주세요.'
    topics=find_topics([combined])
    emotion=next((name for name,words in EMOTIONS.items() if any(w in combined for w in words)),None)
    lead=('표현에서 '+emotion+'의 단서를 찾았어요. 실제 마음과 다를 수도 있어요. ' if emotion else '정확한 마음을 제가 단정할 수는 없어요. ')
    if topics:
        item=data['solutions'][0]
        return lead+'확인해 볼 주제는 '+topics[0][0]+'이에요. '+item['action']+' 지금은 이런 방법을 찾고 싶은가요, 아니면 감정을 더 정리하고 싶은가요?'
    if emotion:
        return lead+'지금은 감정을 말로 정리해 보는 것도 괜찮아요. “나는 ___하게 느껴. 그때 ___가 필요했어.”에서 빈칸 하나부터 채워볼까요? 구체적인 이름이나 사건은 쓰지 않아도 돼요.'
    return '이 문장은 정해진 규칙만으로 충분히 이해하기 어려워요. 제가 이해한 척 답하지는 않을게요. “속상해”, “집안일이 불공평해”, “부탁하는 문장 만들어 줘”처럼 필요한 도움을 짧게 알려주세요. 일반 지식 질문이나 전문 상담은 제공하지 못해요.'

RID=st.session_state.room
with db() as c:
    if not c.execute('SELECT 1 FROM rooms WHERE id=?',(RID,)).fetchone(): logout()

@st.dialog('이용 안내 · 안전과 개인정보')
def help_dialog():
    st.write('가족방 비밀번호를 아는 사람은 모두 같은 권한입니다. 작성자를 찾거나 추궁하지 않기로 먼저 약속하세요.')
    st.write('가림 처리는 모든 개인정보를 찾지 못합니다. 문체·사건으로 작성자가 드러날 수 있습니다. 운영자는 서버와 비밀키에 접근할 수 있으므로 완전 익명이 아닙니다.')
    st.write('챗봇은 한국어 표현 사전과 규칙으로 작동하며 부정문·반어를 오해할 수 있습니다. 외부 AI 전송은 없지만 입력은 앱 서버에서 처리됩니다. 챗봇 대화는 현재 접속 세션에만 유지됩니다.')
    st.write('위험한 상황은 공동 대화보다 안전 확보와 전문 도움을 우선하세요. 긴급 위험 112·119 / 청소년 상담 1388 / 자살예방상담 109. 앱은 신고·상담을 대신하지 않습니다.')
    st.warning('현재 SQLite 시제품은 Streamlit Community Cloud 재시작·재배포 시 기록이 사라질 수 있습니다. 장기 운영에는 영속 DB가 필요합니다.')
    st.caption('기준 화면: 1366×768 이상, 배율 100%. 작은 창·확대·접근성 글꼴에서는 필요한 스크롤을 허용합니다. 안내와 편집은 별도 팝업입니다.')

@st.dialog('공개 전 문장 확인')
def publish_dialog(body):
    st.write(body)
    st.caption('이름·장소·날짜·특정 사건이 남아 있으면 창을 닫고 수정하세요. 자동 가림은 불완전합니다.')
    yes=st.checkbox('신원을 추측할 정보가 없는지 확인했습니다.')
    if st.button('이 문장을 익명으로 공개',type='primary',disabled=not yes):
        import time
        token=secrets.token_urlsafe(18)
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            count=c.execute('SELECT COUNT(*) FROM opinions WHERE room=?',(RID,)).fetchone()[0]
            last=c.execute('SELECT last FROM attempts WHERE room=?',(RID,)).fetchone()
            if count>=100: st.error('방당 100개까지 보관합니다.')
            elif last and time.time()-last[0]<10: st.warning('방 전체에서 10초 간격으로 제출할 수 있습니다.')
            else:
                c.execute('INSERT INTO opinions VALUES(?,?,?,?,?)',(secrets.token_hex(16),RID,seal(body),digest('delete:'+token),now()))
                c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?)',(RID,time.time()))
                st.session_state.receipt=token
                st.session_state.reset_draft=True
                st.rerun()

@st.dialog('내 의견 삭제코드')
def receipt_dialog():
    st.caption('가장 최근 제출의 코드입니다. 별도 보관하세요. 이전 제출 코드는 복구할 수 없습니다.')
    st.code(st.session_state.get('receipt','아직 이 접속에서 제출한 의견이 없습니다.'))

@st.dialog('내가 남긴 의견 삭제')
def delete_dialog():
    code=st.text_input('제출 당시 받은 삭제코드',type='password')
    if st.button('이 의견 삭제',type='primary'):
        with db() as c:
            n=c.execute('DELETE FROM opinions WHERE room=? AND deletion_hash=?',(RID,digest('delete:'+code))).rowcount
        if n:
            st.session_state.pop('analysis',None)
            st.rerun()
        else: st.error('일치하는 코드가 없습니다.')

@st.dialog('가족의 7일 실천')
def plan_dialog():
    with db() as c: row=c.execute('SELECT body FROM plans WHERE room=?',(RID,)).fetchone()
    old=json.loads(unseal(row[0])) if row else {}
    with st.form('plan'):
        action=st.text_input('함께 합의한 행동 하나',old.get('action','대화할 때 2분 동안 끼어들지 않고 듣기'),max_chars=160)
        measure=st.text_input('돌아볼 질문',old.get('measure','내 이야기를 충분히 들었다고 느꼈나요?'),max_chars=160)
        reflection=st.text_area('공동 회고 · 개인 지목 금지',old.get('reflection',''),max_chars=300,height=85)
        yes=st.checkbox('개인정보가 없고 가족이 저장에 동의했습니다.')
        if st.form_submit_button('공동 계획 저장',type='primary'):
            if yes and action.strip():
                data={k:redact(v) for k,v in {'action':action,'measure':measure,'reflection':reflection}.items()}
                with db() as c: c.execute('INSERT OR REPLACE INTO plans VALUES(?,?,?)',(RID,seal(json.dumps(data,ensure_ascii=False)),now()))
                st.rerun()
            else: st.warning('실천 내용과 동의를 확인하세요.')

@st.dialog('가족방 전체 삭제')
def room_delete_dialog():
    st.warning('모든 의견·계획·가족방이 삭제됩니다. 가족과 합의하세요. 호스팅 백업이나 다른 접속자의 열린 화면까지 지우지는 못합니다.')
    pw=st.text_input('방 비밀번호',type='password')
    phrase=st.text_input('확인 문구: 가족방 삭제')
    yes=st.checkbox('가족과 합의했으며 되돌릴 수 없음을 이해했습니다.')
    if st.button('가족방 영구 삭제',type='primary'):
        with db() as c:
            row=c.execute('SELECT salt,verifier FROM rooms WHERE id=?',(RID,)).fetchone()
            ok=row and yes and phrase=='가족방 삭제' and hmac.compare_digest(verifier(pw,row[0]),row[1])
            if ok: c.execute('DELETE FROM rooms WHERE id=?',(RID,))
        if ok: logout()
        else: st.error('비밀번호와 확인 항목을 확인하세요.')

def chunks(text,n=210):
    # 긴 내용을 숨기거나 자르지 않고 작은 페이지로 모두 제공.
    return [text[i:i+n] for i in range(0,len(text),n)] or ['아직 내용이 없습니다.']

if st.session_state.pop('reset_draft',False):
    st.session_state.draft=''
    st.session_state.extra=''
opinions=get_opinions()
left,mid,right=st.columns([6,2,2])
with left: st.caption('이름 대신 마음에 집중해요 · 의견 '+str(len(opinions))+'개 · 규칙 기반 도우미')
with mid:
    if st.button('이용 안내',use_container_width=True): help_dialog()
with right:
    if st.button('나가기',use_container_width=True): logout()

write_col,feed_col,helper_col=st.columns([1,1,1.18],gap='medium')
with write_col:
    with st.container(border=True):
        st.subheader('01  마음 남기기')
        st.caption('구체적인 사람·사건 대신 감정과 바라는 점을 적어주세요.')
        text=st.text_area('내 마음',height=145,max_chars=500,key='draft',placeholder='나는 ___하게 느껴. 내게 ___가 필요해.',label_visibility='collapsed')
        extra=st.text_input('추가로 가릴 이름·장소',max_chars=200,key='extra',placeholder='쉼표로 구분 · 저장되지 않음')
        if st.button('가린 문장 확인 후 공개',type='primary',use_container_width=True):
            safe=redact(text,extra)
            if len(safe)<10: st.warning('10자 이상 적어주세요.')
            else: publish_dialog(safe)
        a,b=st.columns(2)
        with a:
            if st.button('삭제코드 확인',use_container_width=True): receipt_dialog()
        with b:
            if st.button('내 의견 삭제',use_container_width=True): delete_dialog()
        if st.session_state.get('receipt'): st.caption('✓ 최근 의견을 저장했습니다. 삭제코드를 보관하세요.')
        else: st.caption('자동 가림은 불완전합니다. 공개 전 직접 확인하세요.')
with feed_col:
    with st.container(border=True):
        st.subheader('02  서로의 여백')
        st.caption('작성자·시각 없이 읽어요. 의견 수는 사람 수가 아닙니다.')
        ids=[i for i,_ in opinions]
        if set(st.session_state.get('order',[]))!=set(ids):
            order=list(ids);random.SystemRandom().shuffle(order)
            st.session_state.order=order
        if st.button('순서 다시 섞기',use_container_width=True):
            random.SystemRandom().shuffle(st.session_state.order)
            st.rerun()
        byid=dict(opinions)
        order=st.session_state.get('order',[])
        if order:
            chosen=st.selectbox('읽을 의견',range(len(order)),format_func=lambda i:'익명 의견 '+str(i+1),key='opinion_choice')
            parts=chunks(byid[order[chosen]],180)
            part=st.select_slider('문장 페이지',options=list(range(len(parts))),format_func=lambda i:str(i+1)+' / '+str(len(parts)),key='opinion_part') if len(parts)>1 else 0
            st.write(parts[part])
        else: st.info('첫 번째 마음을 남겨주세요.')
        st.caption('작성자 추측·비난·보복 없이 읽기로 약속해요.')
with helper_col:
    with st.container(border=True):
        st.subheader('03  마음의 길잡이')
        mode=st.radio('도움 종류',['의견 살펴보기','대화하기'],horizontal=True,label_visibility='collapsed')
        if mode=='의견 살펴보기':
            if st.button('모인 의견 분석',type='primary',use_container_width=True):
                if len(opinions)<3: st.warning('의견 3개 이상이 필요합니다.')
                else:
                    st.session_state.analysis=analyze_local([b for _,b in opinions])
                    st.session_state.fingerprint=digest(json.dumps(sorted(i for i,_ in opinions)))
            data=st.session_state.get('analysis')
            if not data: st.caption('감정·필요의 단서를 찾고, 해결 방법 3가지를 제안해요. 원인이나 잘잘못을 판정하지 않습니다.')
            else:
                if st.session_state.get('fingerprint')!=digest(json.dumps(sorted(i for i,_ in opinions))): st.caption('⚠ 의견이 바뀌었습니다. 다시 분석하세요.')
                sections=[]
                for label,key in [('감정 단서','emotions'),('필요 단서','common_needs'),('놓치지 않을 점','differences'),('원인 가설','causes')]:
                    sections.extend((label+' '+str(i+1),v) for i,v in enumerate(data[key]))
                for i,item in enumerate(data['solutions'],1):
                    sections.append(('해결 방법 '+str(i),item['title']+'\n\n'+item['action']+'\n\n확인: '+item['check']))
                sections.extend(('대화 예시 '+str(i+1),v) for i,v in enumerate(data['conversation']))
                sections.append(('안전·분석 한계',data['safety']))
                selected=st.selectbox('결과 항목',range(len(sections)),format_func=lambda i:sections[i][0])
                for_index=chunks(sections[selected][1],230)
                step=st.select_slider('결과 페이지',options=list(range(len(for_index))),format_func=lambda i:str(i+1)+' / '+str(len(for_index)),key='result_page') if len(for_index)>1 else 0
                st.write(for_index[step])
        else:
            st.caption('감정 정리·요청 문장·작은 실천을 도와요. 전문 상담이나 생성형 AI가 아닙니다.')
            history=st.session_state.get('chat',[])
            if history:
                # 답변 원문 전체는 페이지 전환으로 열람 가능.
                reply=history[-1]['content']
                parts=chunks(reply,220)
                page=st.select_slider('답변 페이지',options=list(range(len(parts))),format_func=lambda i:str(i+1)+' / '+str(len(parts)),key='reply_page') if len(parts)>1 else 0
                st.write(parts[page])
            else: st.write('지금 어떤 마음인가요? 이름이나 특정 사건은 적지 않아도 괜찮아요.')
            with st.form('chat_form',clear_on_submit=True):
                prompt=st.text_input('도우미에게 말하기',max_chars=500,placeholder='예: 내 말을 안 들어줘서 속상해')
                send=st.form_submit_button('이야기 보내기',use_container_width=True)
            if send and prompt.strip():
                clean=redact(prompt)
                reply=chat_reply(clean,history)
                st.session_state.chat=(history+[{'role':'user','content':clean},{'role':'assistant','content':reply}])[-20:]
                st.session_state.pop('reply_page',None)
                st.rerun()
            if st.button('대화 지우기',use_container_width=True):
                st.session_state.chat=[]
                st.rerun()

st.divider()
with db() as c: row=c.execute('SELECT body FROM plans WHERE room=?',(RID,)).fetchone()
plan=json.loads(unseal(row[0])) if row else {}
a,b,c=st.columns([6,2,2])
with a:
    action=plan.get('action','아직 정하지 않았어요. 부담 없는 행동 하나를 함께 골라보세요.')
    # 한 줄 요약만 홈에, 원문은 실천 팝업에서 전부 확인.
    st.caption('이번 주 실천 · '+(action[:62]+'…' if len(action)>62 else action))
with b:
    if st.button('7일 실천·회고',use_container_width=True): plan_dialog()
with c:
    if st.button('가족방 삭제',use_container_width=True): room_delete_dialog()
st.caption('개인을 추측하지 않기 · 원치 않는 대화는 중단하기 · 위험할 땐 안전 우선 · 안내·편집은 팝업으로 열립니다.')
