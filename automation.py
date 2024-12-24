from diagnostic_a import DiagnosticA
from diagnostic_b import DiagnosticB
from diagnostic_c import DiagnosticC
from diagnostic_d import DiagnosticD
from report_excel import Report
from tqdm import tqdm

# Report class 선언
report = Report()

# 진단 선언
diagnostic_a = DiagnosticA("aws_credentials.json")
diagnostic_b = DiagnosticB("aws_credentials.json")
diagnostic_c = DiagnosticC("aws_credentials.json")
diagnostic_d = DiagnosticD("aws_credentials.json")

# 전체 진단 결과를 담아줄 리스트
result = []

# 각 진단 항목 정의
diagnostic_tasks = [
    {"name": "A01", "method": diagnostic_a.A01},
    {"name": "A02", "method": diagnostic_a.A02},
    {"name": "A03", "method": diagnostic_a.A03},
    {"name": "A04", "method": diagnostic_a.A04},
    {"name": "A05", "method": diagnostic_a.A05},
    {"name": "A06", "method": diagnostic_a.A06},
    {"name": "A07", "method": diagnostic_a.A07},
    {"name": "A08", "method": diagnostic_a.A08},
    {"name": "A09", "method": diagnostic_a.A09},
    {"name": "A10", "method": diagnostic_a.A10},
    {"name": "B01", "method": diagnostic_b.B01},
    {"name": "B02", "method": diagnostic_b.B02},
    {"name": "B03", "method": diagnostic_b.B03},
    {"name": "C01", "method": diagnostic_c.C01},
    {"name": "C02", "method": diagnostic_c.C02},
    {"name": "C03", "method": diagnostic_c.C03},
    {"name": "C04", "method": diagnostic_c.C04},
    {"name": "C05", "method": diagnostic_c.C05},
    {"name": "C06", "method": diagnostic_c.C06},
    {"name": "C07", "method": diagnostic_c.C07},
    {"name": "C08", "method": diagnostic_c.C08},
    {"name": "D01", "method": diagnostic_d.D01},
    {"name": "D02", "method": diagnostic_d.D02},
    {"name": "D03", "method": diagnostic_d.D03},
    {"name": "D04", "method": diagnostic_d.D04},
    {"name": "D05", "method": diagnostic_d.D05},
    {"name": "D06", "method": diagnostic_d.D06},
    {"name": "D07", "method": diagnostic_d.D07},
    {"name": "D08", "method": diagnostic_d.D08},
    {"name": "D09", "method": diagnostic_d.D09},
    {"name": "D10", "method": diagnostic_d.D10},
    {"name": "D11", "method": diagnostic_d.D11},
    {"name": "D12", "method": diagnostic_d.D12},
    {"name": "D13", "method": diagnostic_d.D13},
]

# 진단 실행 및 프로그레스바 표시
print("=== 진단을 시작합니다 ===")
with tqdm(total=len(diagnostic_tasks), desc="진단 진행 중", unit="task", ncols=80) as pbar:
    for task in diagnostic_tasks:
        # 진단 실행
        result.append({task["name"].lower(): task["method"]()})
        # 프로그레스바 업데이트
        pbar.set_description(f"진단 {task['name']} 완료")
        pbar.update(1)

# Report 생성
report.overwrite(result)
report.save("diagnostic_report")
print("\n=== 진단 완료 및 보고서 저장 완료 ===")