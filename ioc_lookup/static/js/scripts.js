$(document).ready(function() {
    $(".btn").click(function() {
      // disable button
      $(this).prop("disabled", true);
      // add spinner to button
      $(this).html(
        `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...`
      );
      // submit form due to a Chrome bug
      // https://stackoverflow.com/questions/16867080/onclick-javascript-stops-form-submit-in-chrome
      $(this).parent().submit()
    });
});
