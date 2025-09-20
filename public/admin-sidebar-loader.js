// 공통 관리자 사이드바 로더
async function loadAdminSidebar() {
    try {
        const response = await fetch('/admin-sidebar.html');
        if (!response.ok) {
            throw new Error(`사이드바 로드 실패: ${response.status}`);
        }
        
        const sidebarHTML = await response.text();
        
        // 기존 사이드바가 있으면 제거
        const existingSidebar = document.querySelector('aside');
        if (existingSidebar) {
            existingSidebar.remove();
        }
        
        // 메인 레이아웃의 flex div 찾기
        const mainLayout = document.querySelector('.flex');
        if (mainLayout) {
            // 사이드바를 첫 번째 자식으로 삽입
            mainLayout.insertAdjacentHTML('afterbegin', sidebarHTML);
        } else {
            console.error('메인 레이아웃 (.flex) 요소를 찾을 수 없습니다');
        }
        
        console.log('✅ 관리자 사이드바 로드 완료');
        
    } catch (error) {
        console.error('❌ 사이드바 로드 실패:', error);
    }
}

// 헤더에 모바일 메뉴 버튼 추가
function addMobileMenuButton() {
    const header = document.querySelector('header .flex');
    if (!header) return;
    
    // 기존 모바일 버튼이 있으면 제거
    const existingButton = header.querySelector('.mobile-menu-button');
    if (existingButton) {
        existingButton.remove();
    }
    
    // 로고 요소 찾기
    const logo = header.querySelector('div.flex.items-center');
    if (logo) {
        // 모바일 메뉴 버튼을 로고 앞에 추가
        logo.insertAdjacentHTML('beforebegin', `
            <button onclick="openMobileDrawer()" class="mobile-menu-button lg:hidden p-2 rounded-md text-gray-600 hover:text-blue-600 hover:bg-gray-100 transition-colors">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                </svg>
            </button>
        `);
    }
}

// 페이지 로드 시 사이드바 자동 로드
document.addEventListener('DOMContentLoaded', async () => {
    await loadAdminSidebar();
    addMobileMenuButton();
});

// 로그아웃 함수 (모든 관리자 페이지에서 공통 사용)
async function logout() {
    try {
        await fetch('/admin/logout', { method: 'POST' });
        window.location.href = '/admin/login';
    } catch (error) {
        window.location.href = '/admin/login';
    }
}