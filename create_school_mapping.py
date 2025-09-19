#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json

def create_school_mapping():
    # 교육청별로 데이터 분리
    education_offices = {
        'B10': '서울', 'C10': '부산', 'D10': '대구', 'E10': '인천',
        'F10': '광주', 'G10': '대전', 'H10': '울산', 'I10': '세종',
        'J10': '경기', 'K10': '강원', 'M10': '충북', 'N10': '충남',
        'P10': '전북', 'Q10': '전남', 'R10': '경북', 'S10': '경남', 'T10': '제주'
    }
    
    # 교육청별 매핑 딕셔너리 초기화
    regional_mappings = {}
    for office_code, region_name in education_offices.items():
        regional_mappings[office_code] = {
            "school_to_code": {},
            "code_to_school": {},
            "region_name": region_name,
            "office_code": office_code
        }
    
    csv_path = '/Users/pyojongseung/work/timetable-upload-server/schools_utf8.csv'
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for i, row in enumerate(reader):
                office_code = row['시도교육청코드']
                school_code = row['행정표준코드'] 
                school_name = row['학교명']
                region = row['시도명']
                
                full_code = f"{office_code}_{school_code}"
                
                # 원본 CSV 데이터를 바로 교육청별로 분류
                if office_code in regional_mappings:
                    # 교육청별로 직접 저장 (중복 없음)
                    regional_mappings[office_code]["school_to_code"][school_name] = full_code
                    regional_mappings[office_code]["code_to_school"][full_code] = school_name
                    
                    if school_name == "세화고등학교":
                        print(f"🔍 세화고등학교 발견: {office_code} → {full_code}")
        
    
    except Exception as e:
        print(f"❌ CSV 읽기 실패: {e}")
        return None
    
    total_schools = sum(len(mapping["school_to_code"]) for mapping in regional_mappings.values())
    print(f"✅ CSV 처리 완료: {total_schools}개 학교 (교육청별 분리)")
    
    # 정규식 기반 약자 규칙 (우선순위 순서)
    import re
    abbreviation_patterns = [
        # 특수: 사범대학 부설/부속 (먼저!)
        (r'사범대학\s*(?:부설|부속)\s*고등학교$', '사대부고'),
        (r'사범대학\s*(?:부설|부속)\s*(?:중등학교|중학교)$', '사대부중'),
        (r'사범대학\s*(?:부설|부속)\s*초등학교$', '사대부초'),
        
        # 일반: 부설/부속 (그다음)
        (r'(?:부설|부속)\s*고등학교$', '부고'),
        (r'(?:부설|부속)\s*(?:중등학교|중학교)$', '부중'),
        (r'(?:부설|부속)\s*초등학교$', '부초'),
        
        # 고등학교 계열
        (r'여자고등학교$', '여고'),
        (r'남자고등학교$', '남고'),
        (r'외국어고등학교$', '외고'),
        (r'방송통신고등학교$', '방통고'),
        (r'과학고등학교$', '과고'),
        (r'예술고등학교$', '예고'),
        (r'체육고등학교$', '체고'),
        (r'공업고등학교$', '공고'),
        (r'상업고등학교$', '상고'),
        (r'정보고등학교$', '정보고'),
        (r'국제고등학교$', '국제고'),
        
        # 중학교 계열
        (r'국제중학교$', '국제중'),
        (r'여자중학교$', '여중'),
        (r'남자중학교$', '남중'),
        
        # 일반 (마지막)
        (r'고등학교$', '고'),
        (r'중학교$', '중'),
        (r'초등학교$', '초'),
    ]

    # 각 교육청별로 독립적으로 약자 생성
    for office_code, mapping_data in regional_mappings.items():
        region_name = mapping_data["region_name"]
        original_school_to_code = dict(mapping_data["school_to_code"])
        new_school_to_code = {}
        
        print(f"\n🔍 {region_name}({office_code}) 약자 생성 시작...")
        
        for school_name, full_code in original_school_to_code.items():
            # 원본 학교명 추가
            new_school_to_code[school_name] = full_code
            
            # 바로 밑에 해당 학교의 약자 추가
            for pattern, replacement in abbreviation_patterns:
                if re.search(pattern, school_name):
                    abbreviated_name = re.sub(pattern, replacement, school_name)
                    new_school_to_code[abbreviated_name] = full_code
                    print(f"✅ {region_name} 약자: {school_name} → {abbreviated_name}")
                    break  # 첫 번째 매칭되는 패턴만 적용
        
        # 교육청별 매핑 업데이트
        mapping_data["school_to_code"] = new_school_to_code
    
    # 교육청별 JSON 파일 생성
    import os
    mapping_dir = '/Users/pyojongseung/work/timetable-upload-server/school_mappings'
    os.makedirs(mapping_dir, exist_ok=True)
    
    total_schools = 0
    total_codes = 0
    
    try:
        for office_code, mapping_data in regional_mappings.items():
            region_name = mapping_data["region_name"]
            output_path = f"{mapping_dir}/{office_code}_{region_name}.json"
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(mapping_data, f, ensure_ascii=False, indent=2)
            
            school_count = len(mapping_data["school_to_code"])
            code_count = len(mapping_data["code_to_school"])
            total_schools += school_count
            total_codes += code_count
            
            print(f"✅ {region_name}({office_code}) 매핑 파일 생성: {school_count}개 학교명, {code_count}개 코드")
        
        print(f"\n📊 전체 통계:")
        print(f"  - 총 {len(education_offices)}개 교육청")
        print(f"  - 총 학교명 매핑: {total_schools}개")
        print(f"  - 총 코드 매핑: {total_codes}개")
        print(f"  - 매핑 파일 위치: {mapping_dir}/")
        
        # 세화고 테스트
        print(f"\n🔍 세화고 매핑 테스트:")
        for office_code, region_name in education_offices.items():
            mapping = regional_mappings[office_code]
            if "세화고" in mapping["school_to_code"]:
                code = mapping["school_to_code"]["세화고"]
                print(f"  {region_name}: 세화고 → {code}")
                
    except Exception as e:
        print(f"❌ 교육청별 파일 저장 실패: {e}")

if __name__ == "__main__":
    create_school_mapping()