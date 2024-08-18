$(document).ready(function(){
    // Example: Alert topic name when clicking on a topic
    $('li').on('click', function() {
        alert("You selected: " + $(this).text());
    });

    // Smooth scrolling for anchor links (if you have any)
    $('a[href*="#"]').on('click', function(event) {
        event.preventDefault();
        $('html, body').animate({
            scrollTop: $($.attr(this, 'href')).offset().top
        }, 500);
    });
});
